# -*- coding: utf-8 -*-
"""
IA2IA relay v0.1 — servidor central (stdlib pura).

Transporta peticiones y decisiones entre participantes identificados. NO ejecuta
acciones: solo enruta. Autenticacion por firma HMAC (ver protocolo.md).

Uso:
    python relay.py                 # escucha en 0.0.0.0:8790
    IA2IA_PORT=9000 python relay.py

Config de participantes: identidades.json (copia identidades.example.json).
"""
import os
import json
import time
import hmac
import hashlib
import sqlite3
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

AQUI = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(AQUI, "ia2ia.db")
IDENT = os.path.join(AQUI, "identidades.json")
VENTANA_TS = 300  # segundos de tolerancia anti-replay


def cargar_identidades():
    with open(IDENT, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {p["id"]: p for p in data["participantes"]}


def db():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS peticiones(
        id TEXT PRIMARY KEY, de TEXT, para TEXT, accion TEXT, params TEXT,
        estado TEXT, motivo TEXT, resultado TEXT, creada REAL, decidida REAL)""")
    return con


def firma(secret, ident, ts, metodo, path, body):
    base = f"{ident}\n{ts}\n{metodo}\n{path}\n{body}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()


class H(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _cuerpo(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode("utf-8") if n else ""

    def _verificar(self, metodo, path, body):
        """Devuelve el id del emisor si la firma es valida; si no, None + error."""
        ident = self.headers.get("X-IA2IA-Id")
        ts = self.headers.get("X-IA2IA-Ts")
        sig = self.headers.get("X-IA2IA-Sig")
        if not (ident and ts and sig):
            return None, "faltan cabeceras de firma"
        parts = cargar_identidades().get(ident)
        if not parts:
            return None, f"participante desconocido: {ident}"
        try:
            if abs(time.time() - float(ts)) > VENTANA_TS:
                return None, "timestamp fuera de ventana (replay?)"
        except ValueError:
            return None, "timestamp invalido"
        esperada = firma(parts["secret"], ident, ts, metodo, path, body)
        if not hmac.compare_digest(esperada, sig):
            return None, "firma invalida"
        return ident, None

    # ---- GET ----
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/salud":
            return self._json(200, {"ok": True, "servicio": "ia2ia", "v": "0.1"})
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
                "SELECT id,de,para,accion,params,creada FROM peticiones "
                "WHERE para=? AND estado='PENDIENTE' ORDER BY creada", (para,)).fetchall()
            con.close()
            return self._json(200, {"pendientes": [
                {"peticion_id": r[0], "de": r[1], "para": r[2], "accion": r[3],
                 "params": json.loads(r[4]), "creada": r[5]} for r in rows]})
        if u.path == "/estado":
            pid = (q.get("peticion_id") or [None])[0]
            con = db()
            r = con.execute("SELECT id,de,para,accion,estado,motivo,resultado FROM "
                            "peticiones WHERE id=?", (pid,)).fetchone()
            con.close()
            if not r:
                return self._json(404, {"error": "no existe"})
            if emisor not in (r[1], r[2]):
                return self._json(403, {"error": "no eres parte de esta peticion"})
            return self._json(200, {"peticion_id": r[0], "de": r[1], "para": r[2],
                "accion": r[3], "estado": r[4], "motivo": r[5],
                "resultado": json.loads(r[6]) if r[6] else None})
        return self._json(404, {"error": "ruta desconocida"})

    # ---- POST ----
    def do_POST(self):
        body = self._cuerpo()
        emisor, err = self._verificar("POST", self.path, body)
        if err:
            return self._json(401, {"error": err})
        try:
            data = json.loads(body or "{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "JSON invalido"})
        idents = cargar_identidades()

        if self.path == "/peticion":
            para = data.get("to")
            if para not in idents:
                return self._json(400, {"error": f"destinatario desconocido: {para}"})
            pid = secrets.token_hex(8)
            con = db()
            con.execute("INSERT INTO peticiones VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (pid, emisor, para, data.get("accion", ""),
                         json.dumps(data.get("params", {}), ensure_ascii=False),
                         "PENDIENTE", None, None, time.time(), None))
            con.commit(); con.close()
            return self._json(201, {"peticion_id": pid, "estado": "PENDIENTE"})

        if self.path == "/decidir":
            pid = data.get("peticion_id")
            decision = data.get("decision")
            con = db()
            r = con.execute("SELECT para,estado FROM peticiones WHERE id=?", (pid,)).fetchone()
            if not r:
                con.close(); return self._json(404, {"error": "no existe"})
            if r[0] != emisor:
                con.close(); return self._json(403, {"error": "solo el destinatario decide"})
            if r[1] != "PENDIENTE":
                con.close(); return self._json(409, {"error": f"ya estaba {r[1]}"})
            nuevo = "AUTORIZADA" if decision == "autorizar" else "RECHAZADA"
            con.execute("UPDATE peticiones SET estado=?, motivo=?, decidida=? WHERE id=?",
                        (nuevo, data.get("motivo"), time.time(), pid))
            con.commit(); con.close()
            return self._json(200, {"peticion_id": pid, "estado": nuevo})

        if self.path == "/resultado":
            pid = data.get("peticion_id")
            con = db()
            r = con.execute("SELECT para,estado FROM peticiones WHERE id=?", (pid,)).fetchone()
            if not r:
                con.close(); return self._json(404, {"error": "no existe"})
            if r[0] != emisor:
                con.close(); return self._json(403, {"error": "solo el destinatario ejecuta"})
            if r[1] != "AUTORIZADA":
                con.close(); return self._json(409, {"error": f"no autorizada (esta {r[1]})"})
            con.execute("UPDATE peticiones SET estado='EJECUTADA', resultado=? WHERE id=?",
                        (json.dumps(data.get("resultado"), ensure_ascii=False), pid))
            con.commit(); con.close()
            return self._json(200, {"peticion_id": pid, "estado": "EJECUTADA"})

        return self._json(404, {"error": "ruta desconocida"})

    def log_message(self, *a):  # silencioso
        pass


if __name__ == "__main__":
    port = int(os.environ.get("IA2IA_PORT", "8790"))
    print(f"IA2IA relay v0.1 escuchando en 0.0.0.0:{port}  (DB: {DB})")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
