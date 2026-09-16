# -*- coding: utf-8 -*-
"""
IA2IA relay v0.2 — servidor central (stdlib + identidad.py).

Transporta peticiones y decisiones entre participantes identificados por
CLAVE CRIPTOGRAFICA (Ed25519). NO ejecuta acciones: solo enruta, aplica
las reglas anti-abuso (protocolo-v0.2.md S6) y guarda auditoria (sqlite).

Novedad frente a v0.1: identidad AUTOCERTIFICADA. El relay no necesita
conocer de antemano a nadie (no hay identidades.json con secretos
compartidos): cada peticion trae su propia clave publica; el relay solo
comprueba que el id declarado es de verdad el hash de esa clave (o, para
una instancia, que el certificado firmado por la raiz lo respalda) y que
la firma de la peticion es valida. Cero registro previo, cero reparto de
secretos.

Uso:
    python relay.py                 # escucha en 0.0.0.0:8790
    IA2IA_PORT=9000 python relay.py
    IA2IA_DB=C:\\ruta\\otra.db python relay.py   # (tests / varios relays)
    IA2IA_ROOTS=<id1>,<id2> python relay.py      # allowlist de root-ids (ver H2)
    IA2IA_ROOTS_FILE=C:\\ruta\\roots.txt python relay.py

NO exponer a internet sin: (1) HTTPS delante (proxy/tunel — responsabilidad de
infraestructura al desplegar; el relay en si NO hace TLS y el puerto 8790 NO
debe quedar accesible fuera de ese tunel), (2) revision de
seguridad-informatica, (3) OK explicito de Santos. Ver protocolo-v0.2.md S8.
"""
import os
import json
import time
import base64
import hashlib
import sqlite3
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import identidad

AQUI = os.path.dirname(os.path.abspath(__file__))
DB_DEFECTO = os.path.join(AQUI, "ia2ia.db")

VENTANA_TS = 300        # segundos de tolerancia anti-replay del timestamp
VENTANA_RATE = 3600     # ventana de la regla "1 peticion/hora"
MAX_PENDIENTES = 5      # peticiones PENDIENTES simultaneas por emisor
MAX_INSISTENCIAS = 3    # reintentos de lo mismo tras rechazo -> escalado
TOPE_BYTES_HORA = 200_000  # proxy de coste: bytes de params por emisor/hora
MAX_BODY_BYTES = 65_536    # tope H3: ninguna peticion legitima pesa mas que esto
# tope de DRENAJE cuando el cuerpo supera MAX_BODY_BYTES (ver _cuerpo(), abajo):
# bien por encima de MAX_BODY_BYTES para no cortar a un cliente legitimo que se
# paso "un poco", pero acotado para que drenar nunca sea en si mismo el vector
# de DoS que H3 queria evitar.
DRENAJE_TOPE_BYTES = MAX_BODY_BYTES * 4

ROOTS_FILE_DEFECTO = os.path.join(AQUI, "roots_permitidos.txt")


def _db_path():
    return os.environ.get("IA2IA_DB", DB_DEFECTO)


def _raices_permitidas() -> set:
    """Allowlist H2 de root-ids autorizados en ESTE relay. Config DEL RELAY,
    nunca de cada cliente (si dependiera de lo que dice el emisor, cualquiera
    podria mintar una identidad gratis y saltarse los limites anti-abuso, que
    van keyed por id, ademas de inundar de avisos a la gente real).

    Se combinan dos fuentes, sin cache (se relee en cada peticion: anadir un
    root no exige reiniciar el relay):
      - fichero (una linea por root-id hex; '#' comenta el resto de la linea),
        ruta en IA2IA_ROOTS_FILE o, por defecto, roots_permitidos.txt junto a
        este fichero.
      - variable de entorno IA2IA_ROOTS, root-ids separados por coma.

    Sin ninguna de las dos, la lista sale VACIA: el relay no admite a NADIE
    (falla cerrado, nunca abierto)."""
    raices = set()
    ruta = os.environ.get("IA2IA_ROOTS_FILE", ROOTS_FILE_DEFECTO)
    if os.path.exists(ruta):
        with open(ruta, "r", encoding="utf-8") as f:
            for linea in f:
                linea = linea.split("#", 1)[0].strip()
                if linea:
                    raices.add(linea)
    for r in os.environ.get("IA2IA_ROOTS", "").split(","):
        r = r.strip()
        if r:
            raices.add(r)
    return raices


def db():
    con = sqlite3.connect(_db_path())
    con.execute("""CREATE TABLE IF NOT EXISTS peticiones(
        id TEXT PRIMARY KEY, de TEXT, para TEXT, accion TEXT, params TEXT,
        estado TEXT, motivo TEXT, resultado TEXT, creada REAL, decidida REAL,
        reclamada_por TEXT, huella TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS nonces(
        id TEXT, nonce TEXT, ts REAL, PRIMARY KEY(id, nonce))""")
    con.execute("""CREATE TABLE IF NOT EXISTS bloqueos(
        bloqueador TEXT, bloqueado TEXT, creada REAL,
        PRIMARY KEY(bloqueador, bloqueado))""")
    con.execute("""CREATE TABLE IF NOT EXISTS avisos(
        id TEXT PRIMARY KEY, para TEXT, de TEXT, mensaje TEXT, creada REAL,
        visto INTEGER DEFAULT 0)""")
    con.execute("""CREATE TABLE IF NOT EXISTS insistencias(
        de TEXT, para TEXT, huella TEXT, veces INTEGER, primera REAL, ultima REAL,
        PRIMARY KEY(de, para, huella))""")
    return con


def _raiz(idv: str) -> str:
    return idv.split(".", 1)[0]


def _huella_peticion(accion: str, params: dict) -> str:
    base = accion + "\n" + json.dumps(params or {}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


ESTADO_A2A = {
    "PENDIENTE": "auth-required",
    "AUTORIZADA": "working",
    "EJECUTADA": "completed",
    "RECHAZADA": "rejected",
    "BLOQUEADA": "blocked",
}


class H(BaseHTTPRequestHandler):
    # ------------------------------------------------------------- utils
    def _json(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _cuerpo(self):
        """Lee el cuerpo, o devuelve None (H3) si el Content-Length declarado
        supera MAX_BODY_BYTES — se comprueba la CABECERA antes de leer nada
        del socket, nunca se llega a bufferizar un cuerpo gigante como JSON.

        Cuando se pasa, y el tamano declarado sigue estando ACOTADO (hasta
        DRENAJE_TOPE_BYTES), se drena igualmente del socket antes de devolver
        None: si no, el emisor legitimo que se paso "un poco" de tamano puede
        seguir escribiendo su cuerpo en el socket mientras el handler ya
        respondio 413 y cerro la conexion, y en Windows eso produce un RST
        (WinError 10053 / ConnectionAbortedError) en vez de dejarle leer la
        respuesta 413 limpia — el cliente ve un corte de conexion no
        determinista en lugar de un error claro. Si el Content-Length
        declarado se pasa TAMBIEN del tope de drenaje, eso ya no es "un poco
        de mas": no se drena y se corta en seco (RST), que es el
        comportamiento correcto ante un abusador de verdad."""
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY_BYTES:
            if n <= DRENAJE_TOPE_BYTES:
                self.rfile.read(n)
            return None
        return self.rfile.read(n).decode("utf-8") if n else ""

    def _verificar(self, metodo, path, body):
        """Devuelve (id_emisor, None) si la firma/identidad son validas,
        o (None, motivo_error) si no. No hay secretos compartidos: todo se
        comprueba con lo que la propia peticion trae (autocertificado)."""
        ident = self.headers.get("X-IA2IA-Id")
        pubkey_hex = self.headers.get("X-IA2IA-PubKey")
        ts = self.headers.get("X-IA2IA-Ts")
        nonce = self.headers.get("X-IA2IA-Nonce")
        sig = self.headers.get("X-IA2IA-Sig")
        cert_b64 = self.headers.get("X-IA2IA-Cert")

        if not (ident and pubkey_hex and ts and nonce and sig):
            return None, "faltan cabeceras de firma (Id/PubKey/Ts/Nonce/Sig)"

        # H2: allowlist de root-ids ANTES de tocar sqlite (y antes de gastar
        # ciclos en verificar certificado/firma) — una raiz no autorizada no
        # llega ni a la base de datos.
        if _raiz(ident) not in _raices_permitidas():
            return None, "raiz no autorizada en este relay"
        try:
            if abs(time.time() - float(ts)) > VENTANA_TS:
                return None, "timestamp fuera de ventana (replay?)"
        except ValueError:
            return None, "timestamp invalido"

        if "." in ident:
            if not cert_b64:
                return None, "falta certificado de instancia (X-IA2IA-Cert)"
            try:
                cert = json.loads(base64.b64decode(cert_b64).decode("utf-8"))
            except Exception:
                return None, "certificado ilegible"
            ok, err = identidad.verificar_cert(cert)
            if not ok:
                return None, f"certificado invalido: {err}"
            if cert["instancia_id"] != ident or cert["instancia_pubkey"] != pubkey_hex:
                return None, "certificado no corresponde al emisor declarado"
        else:
            if identidad.huella(pubkey_hex) != ident:
                return None, "la clave publica no corresponde al id declarado"

        base = f"{ident}\n{ts}\n{nonce}\n{metodo}\n{path}\n{body}".encode("utf-8")
        if not identidad.verificar(pubkey_hex, base, sig):
            return None, "firma invalida"

        con = db()
        try:
            ahora = time.time()
            # H5: purga nonces fuera de la ventana anti-replay en cada peticion
            # valida — la tabla no crece sin limite con el uso normal.
            con.execute("DELETE FROM nonces WHERE ts < ?", (ahora - VENTANA_TS,))
            con.execute("INSERT INTO nonces VALUES(?,?,?)", (ident, nonce, ahora))
            con.commit()
        except sqlite3.IntegrityError:
            con.close()
            return None, "nonce reutilizado (replay?)"
        con.close()
        return ident, None

    def _comprobar_abuso(self, con, emisor, destino, accion, params):
        """Reglas anti-abuso del protocolo (S6), aplicadas por el RELAY.
        Devuelve None si la peticion puede seguir, o el motivo de rechazo."""
        ahora = time.time()

        if con.execute("SELECT 1 FROM bloqueos WHERE bloqueador=? AND bloqueado=?",
                        (_raiz(destino), _raiz(emisor))).fetchone():
            return "bloqueado: el destinatario te ha bloqueado"

        n_pend = con.execute("SELECT COUNT(*) FROM peticiones WHERE de=? AND estado='PENDIENTE'",
                              (emisor,)).fetchone()[0]
        if n_pend >= MAX_PENDIENTES:
            return f"maximo {MAX_PENDIENTES} peticiones pendientes por participante"

        ultima = con.execute("SELECT MAX(creada) FROM peticiones WHERE de=?",
                              (emisor,)).fetchone()[0]
        if ultima and (ahora - ultima) < VENTANA_RATE:
            hubo_interaccion = con.execute(
                "SELECT 1 FROM peticiones WHERE de=? AND decidida IS NOT NULL AND decidida>?",
                (emisor, ahora - VENTANA_RATE)).fetchone()
            if not hubo_interaccion:
                return "limite de 1 peticion/hora sin interaccion humana previa"

        tam = len(json.dumps(params or {}, ensure_ascii=False).encode("utf-8"))
        total = con.execute(
            "SELECT COALESCE(SUM(LENGTH(params)),0) FROM peticiones WHERE de=? AND creada>?",
            (emisor, ahora - VENTANA_RATE)).fetchone()[0]
        if total + tam > TOPE_BYTES_HORA:
            return "tope de tamano/coste por hora superado"

        # "sin auto-reintento tras rechazo, y reenviar lo mismo cuenta para el
        # escalado" (S6). Si ya hubo un rechazo IDENTICO (misma accion+params) de
        # este emisor a este destino, cada nuevo intento identico se bloquea aqui
        # (nunca llega a insertarse como peticion nueva) y suma a un contador propio
        # de insistencia — si contara solo peticiones RECHAZADAS insertadas, los
        # intentos bloqueados no subirian nunca el contador y el escalado no
        # dispararia jamas.
        huella_pet = _huella_peticion(accion, params)
        hubo_rechazo_igual = con.execute(
            "SELECT 1 FROM peticiones WHERE de=? AND para=? AND estado='RECHAZADA' AND huella=?",
            (emisor, destino, huella_pet)).fetchone()
        fila_insist = con.execute(
            "SELECT veces FROM insistencias WHERE de=? AND para=? AND huella=?",
            (emisor, destino, huella_pet)).fetchone()
        if hubo_rechazo_igual or fila_insist:
            veces = (fila_insist[0] if fila_insist else 0) + 1
            con.execute(
                "INSERT INTO insistencias(de,para,huella,veces,primera,ultima) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(de,para,huella) DO UPDATE SET veces=excluded.veces, ultima=excluded.ultima",
                (emisor, destino, huella_pet, veces, ahora, ahora))
            if veces > MAX_INSISTENCIAS:
                con.execute("INSERT INTO avisos VALUES(?,?,?,?,?,0)",
                            (secrets.token_hex(6), destino, emisor,
                             f"'{emisor}' insiste ({veces}x) con '{accion}' pese al rechazo: "
                             f"valora bloquearlo (POST /bloquear).", ahora))
            con.commit()
            return (f"ya se rechazo antes (insistencia {veces}/{MAX_INSISTENCIAS}); "
                    f"no se reenvia sin cambios en accion/params")
        return None

    # ------------------------------------------------------------- GET
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/salud":
            return self._json(200, {"ok": True, "servicio": "ia2ia", "v": "0.2"})

        emisor, err = self._verificar("GET", self.path, "")
        if err:
            return self._json(401, {"error": err})
        q = parse_qs(u.query)

        if u.path == "/bandeja":
            para = (q.get("to") or [None])[0]
            if para != emisor:
                return self._json(403, {"error": "solo puedes leer tu propia bandeja"})
            con = db()
            rows = con.execute(
                "SELECT id,de,para,accion,params,creada,reclamada_por FROM peticiones "
                "WHERE estado='PENDIENTE' AND (para=? OR (para=? AND reclamada_por IS NULL)) "
                "ORDER BY creada", (para, _raiz(para))).fetchall()
            con.close()
            return self._json(200, {"pendientes": [
                {"peticion_id": r[0], "de": r[1], "para": r[2], "accion": r[3],
                 "params": json.loads(r[4]), "creada": r[5],
                 "reclamada": bool(r[6]), "reclamable": r[6] is None} for r in rows]})

        if u.path == "/estado":
            pid = (q.get("peticion_id") or [None])[0]
            con = db()
            r = con.execute("SELECT id,de,para,accion,estado,motivo,resultado,reclamada_por "
                             "FROM peticiones WHERE id=?", (pid,)).fetchone()
            con.close()
            if not r:
                return self._json(404, {"error": "no existe"})
            if _raiz(emisor) not in (_raiz(r[1]), _raiz(r[2])):
                return self._json(403, {"error": "no eres parte de esta peticion"})
            return self._json(200, {"peticion_id": r[0], "de": r[1], "para": r[2],
                "accion": r[3], "estado": r[4], "estado_a2a": ESTADO_A2A.get(r[4], r[4]),
                "motivo": r[5], "resultado": json.loads(r[6]) if r[6] else None,
                "reclamada_por": r[7]})

        if u.path == "/avisos":
            para = (q.get("to") or [None])[0]
            if _raiz(para or "") != _raiz(emisor):
                return self._json(403, {"error": "solo puedes leer tus propios avisos"})
            con = db()
            rows = con.execute("SELECT id,de,mensaje,creada FROM avisos WHERE para=? "
                                "ORDER BY creada DESC", (_raiz(emisor),)).fetchall()
            con.close()
            return self._json(200, {"avisos": [
                {"aviso_id": r[0], "de": r[1], "mensaje": r[2], "creada": r[3]} for r in rows]})

        return self._json(404, {"error": "ruta desconocida"})

    # ------------------------------------------------------------- POST
    def do_POST(self):
        body = self._cuerpo()
        if body is None:
            return self._json(413, {"error": f"cuerpo demasiado grande "
                                              f"(maximo {MAX_BODY_BYTES} bytes)"})
        emisor, err = self._verificar("POST", self.path, body)
        if err:
            return self._json(401, {"error": err})
        try:
            data = json.loads(body or "{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "JSON invalido"})

        if self.path == "/peticion":
            para = data.get("to")
            accion = data.get("accion", "")
            params = data.get("params", {})
            if not para or not isinstance(para, str):
                return self._json(400, {"error": "falta 'to'"})
            con = db()
            motivo_abuso = self._comprobar_abuso(con, emisor, para, accion, params)
            if motivo_abuso:
                con.close()
                return self._json(429, {"error": motivo_abuso})
            pid = secrets.token_hex(8)
            reclamada_por = para if "." in para else None  # directa a instancia: sin candado
            con.execute("INSERT INTO peticiones VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (pid, emisor, para, accion,
                         json.dumps(params, ensure_ascii=False),
                         "PENDIENTE", None, None, time.time(), None,
                         reclamada_por, _huella_peticion(accion, params)))
            con.commit(); con.close()
            return self._json(201, {"peticion_id": pid, "estado": "PENDIENTE",
                                     "estado_a2a": ESTADO_A2A["PENDIENTE"]})

        if self.path == "/reclamar":
            pid = data.get("peticion_id")
            if "." not in emisor:
                return self._json(400, {"error": "solo una INSTANCIA puede reclamar "
                                                   "(la raiz no necesita reclamar lo suyo)"})
            con = db()
            r = con.execute("SELECT para, reclamada_por, estado FROM peticiones WHERE id=?",
                             (pid,)).fetchone()
            if not r:
                con.close(); return self._json(404, {"error": "no existe"})
            para, reclamada_previa, est = r
            if para != _raiz(emisor):
                con.close()
                return self._json(403, {"error": "esta peticion no es para tu raiz"})
            if est != "PENDIENTE":
                con.close(); return self._json(409, {"error": f"ya estaba {est}"})
            cur = con.execute(
                "UPDATE peticiones SET reclamada_por=? WHERE id=? AND para=? AND reclamada_por IS NULL",
                (emisor, pid, para))
            con.commit()
            gano = cur.rowcount == 1
            if not gano:
                r2 = con.execute("SELECT reclamada_por FROM peticiones WHERE id=?", (pid,)).fetchone()
                con.close()
                return self._json(409, {"error": "ya reclamada por otra instancia",
                                         "reclamada_por": r2[0] if r2 else None})
            con.close()
            return self._json(200, {"peticion_id": pid, "reclamada_por": emisor})

        if self.path == "/decidir":
            pid = data.get("peticion_id")
            decision = data.get("decision")
            con = db()
            r = con.execute("SELECT para,reclamada_por,estado FROM peticiones WHERE id=?",
                             (pid,)).fetchone()
            if not r:
                con.close(); return self._json(404, {"error": "no existe"})
            para, reclamada_por, est = r
            efectivo = reclamada_por or para
            if efectivo != emisor:
                con.close()
                return self._json(403, {"error": "solo el destinatario (o quien la reclamo) decide"})
            if est != "PENDIENTE":
                con.close(); return self._json(409, {"error": f"ya estaba {est}"})
            nuevo = "AUTORIZADA" if decision == "autorizar" else "RECHAZADA"
            con.execute("UPDATE peticiones SET estado=?, motivo=?, decidida=? WHERE id=?",
                        (nuevo, data.get("motivo"), time.time(), pid))
            con.commit(); con.close()
            return self._json(200, {"peticion_id": pid, "estado": nuevo,
                                     "estado_a2a": ESTADO_A2A[nuevo]})

        if self.path == "/resultado":
            pid = data.get("peticion_id")
            con = db()
            r = con.execute("SELECT para,reclamada_por,estado FROM peticiones WHERE id=?",
                             (pid,)).fetchone()
            if not r:
                con.close(); return self._json(404, {"error": "no existe"})
            para, reclamada_por, est = r
            efectivo = reclamada_por or para
            if efectivo != emisor:
                con.close(); return self._json(403, {"error": "solo quien ejecuta publica el resultado"})
            if est != "AUTORIZADA":
                con.close(); return self._json(409, {"error": f"no autorizada (esta {est})"})
            con.execute("UPDATE peticiones SET estado='EJECUTADA', resultado=? WHERE id=?",
                        (json.dumps(data.get("resultado"), ensure_ascii=False), pid))
            con.commit(); con.close()
            return self._json(200, {"peticion_id": pid, "estado": "EJECUTADA",
                                     "estado_a2a": ESTADO_A2A["EJECUTADA"]})

        if self.path == "/bloquear":
            objetivo = _raiz(data.get("id") or "")
            if not objetivo:
                return self._json(400, {"error": "falta 'id'"})
            con = db()
            con.execute("INSERT OR IGNORE INTO bloqueos VALUES(?,?,?)",
                        (_raiz(emisor), objetivo, time.time()))
            con.commit(); con.close()
            return self._json(200, {"bloqueador": _raiz(emisor), "bloqueado": objetivo})

        if self.path == "/desbloquear":
            objetivo = _raiz(data.get("id") or "")
            con = db()
            con.execute("DELETE FROM bloqueos WHERE bloqueador=? AND bloqueado=?",
                        (_raiz(emisor), objetivo))
            con.commit(); con.close()
            return self._json(200, {"bloqueador": _raiz(emisor), "desbloqueado": objetivo})

        return self._json(404, {"error": "ruta desconocida"})

    def log_message(self, *a):  # silencioso
        pass


if __name__ == "__main__":
    port = int(os.environ.get("IA2IA_PORT", "8790"))
    print(f"IA2IA relay v0.2 escuchando en 0.0.0.0:{port}  (DB: {_db_path()})")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
