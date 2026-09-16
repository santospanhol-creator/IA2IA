# -*- coding: utf-8 -*-
"""
IA2IA cliente/CLI v0.2 — lo usan AMBOS lados (Santos y Abraham).

Firma cada llamada con tu clave Ed25519 (identidad.py) y habla con el
relay. Incluye el gate humano: `servir` aplica primero tu politica.json
(denylist/allowlist) y, si no basta para decidir sola, avisa y pregunta.

Identidad (junto a este fichero, AMBOS gitignored):
    mi_identidad.json   - tu identidad RAIZ (persona). Obligatoria.
    mi_instancia.json   - identidad de ESTA instancia/maquina. Opcional:
                           si no existe, actuas directo como la raiz
                           (valido para el caso simple, una sola maquina).

Comandos:
    python cliente.py generar-identidad --nombre "HERMES-Santos"
    python cliente.py crear-instancia --sufijo "pc-oficina"
    python cliente.py agenda-anadir --nombre "HERMES-Abraham" --clave-publica <hex>
    python cliente.py bandeja
    python cliente.py enviar --to <nombre-o-id> --accion ping --params '{"hola":1}'
    python cliente.py reclamar <peticion_id>
    python cliente.py autorizar <peticion_id>
    python cliente.py rechazar  <peticion_id> --motivo "no procede"
    python cliente.py estado    <peticion_id>
    python cliente.py avisos
    python cliente.py bloquear   <id>
    python cliente.py desbloquear <id>
    python cliente.py servir            # bucle: politica -> popup -> ejecuta
"""
import os
import sys
import json
import time
import secrets
import argparse
import urllib.request
import urllib.error

import identidad
import agenda
import politica
import notificar

AQUI = os.path.dirname(os.path.abspath(__file__))
RUTA_MI_IDENTIDAD = os.path.join(AQUI, "mi_identidad.json")
RUTA_MI_INSTANCIA = os.path.join(AQUI, "mi_instancia.json")


# --------------------------------------------------------------- identidad

def _leer_json(ruta):
    with open(ruta, "r", encoding="utf-8") as f:
        return json.load(f)


def identidad_raiz() -> dict:
    if not os.path.exists(RUTA_MI_IDENTIDAD):
        sys.exit(f"[!] No existe {RUTA_MI_IDENTIDAD}. Genera la tuya con:\n"
                 f"    python cliente.py generar-identidad --nombre \"tu nombre\"")
    return _leer_json(RUTA_MI_IDENTIDAD)


def identidad_activa() -> dict:
    """La identidad con la que se firma: la instancia activa si existe,
    si no la raiz directamente. Siempre incluye 'relay'."""
    raiz = identidad_raiz()
    relay = os.environ.get("IA2IA_RELAY", raiz.get("relay", "http://127.0.0.1:8790"))
    if os.path.exists(RUTA_MI_INSTANCIA):
        inst = _leer_json(RUTA_MI_INSTANCIA)
        inst["relay"] = relay
        return inst
    raiz["relay"] = relay
    return raiz


# --------------------------------------------------------------- transporte

def _firmar_y_llamar(metodo, path, body_obj=None, ident=None):
    ident = ident or identidad_activa()
    body = json.dumps(body_obj, ensure_ascii=False) if body_obj is not None else ""
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    base = f"{ident['id']}\n{ts}\n{nonce}\n{metodo}\n{path}\n{body}".encode("utf-8")
    sig = identidad.firmar(ident["clave_privada"], base)
    headers = {"Content-Type": "application/json",
               "X-IA2IA-Id": ident["id"], "X-IA2IA-PubKey": ident["clave_publica"],
               "X-IA2IA-Ts": ts, "X-IA2IA-Nonce": nonce, "X-IA2IA-Sig": sig}
    if "cert" in ident:
        import base64
        headers["X-IA2IA-Cert"] = base64.b64encode(
            json.dumps(ident["cert"], ensure_ascii=False).encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        ident["relay"] + path, method=metodo,
        data=body.encode("utf-8") if body else None, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            try:
                return {"error_http": e.code, **json.loads(e.read().decode("utf-8"))}
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {"error_http": e.code, "detalle": "(sin cuerpo legible)"}
        finally:
            e.close()  # si no, ResourceWarning "unclosed" al recogerlo el GC


# --------------------------------------------------------------- API de alto nivel
def enviar(to, accion, params, ident=None):
    return _firmar_y_llamar("POST", "/peticion", {"to": to, "accion": accion, "params": params}, ident)

def bandeja(ident=None):
    ident = ident or identidad_activa()
    return _firmar_y_llamar("GET", f"/bandeja?to={ident['id']}", None, ident)

def reclamar(pid, ident=None):
    return _firmar_y_llamar("POST", "/reclamar", {"peticion_id": pid}, ident)

def decidir(pid, decision, motivo=None, ident=None):
    return _firmar_y_llamar("POST", "/decidir",
                             {"peticion_id": pid, "decision": decision, "motivo": motivo}, ident)

def poner_resultado(pid, resultado, ident=None):
    return _firmar_y_llamar("POST", "/resultado", {"peticion_id": pid, "resultado": resultado}, ident)

def estado(pid, ident=None):
    return _firmar_y_llamar("GET", f"/estado?peticion_id={pid}", None, ident)

def avisos(ident=None):
    ident = ident or identidad_activa()
    return _firmar_y_llamar("GET", f"/avisos?to={ident['id']}", None, ident)

def bloquear(id_objetivo, ident=None):
    return _firmar_y_llamar("POST", "/bloquear", {"id": id_objetivo}, ident)

def desbloquear(id_objetivo, ident=None):
    return _firmar_y_llamar("POST", "/desbloquear", {"id": id_objetivo}, ident)


# --------------------------------------------------------------- ejecutor local
def _ejecutar_accion(accion, params):
    # DEMO. Sustituye por tus funciones reales de negocio (CRM, SQL, flujos...).
    if accion == "ping":
        return {"pong": True, "eco": params}
    return {"aviso": f"accion '{accion}' no implementada en este lado", "params": params}


# --------------------------------------------------------------- servir (gate humano)
def servir(intervalo=5):
    """Bucle principal: politica -> popup -> ejecuta.

    Cuando la politica dice 'preguntar', NUNCA bloquea el bucle esperando
    teclado (esto corre como servicio de fondo, sin consola interactiva
    real - regla de la casa "todo proceso invisible"). Se avisa (Telegram/
    log) y el pid queda en `en_espera_humana`; la decision real llega de
    fuera, como un proceso aparte y de un solo uso:
        python cliente.py autorizar <pid>
        python cliente.py rechazar  <pid> --motivo "..."
    (es exactamente lo que dispara el boton Aprobar/Rechazar de Telegram
    desde el panel). En cada vuelta del bucle se comprueba `estado(pid)`
    para cada pid en espera: si ya esta AUTORIZADA se ejecuta la accion y
    se publica el resultado; si esta RECHAZADA solo se registra; si sigue
    PENDIENTE, se revisa en la proxima vuelta.
    """
    ident = identidad_activa()
    print(f"[servir] escuchando bandeja de {ident['id']} (Ctrl+C para salir)")
    vistos = set()
    en_espera_humana = {}  # pid -> peticion, decidida por 'autorizar'/'rechazar' aparte
    while True:
        b = bandeja(ident)
        for p in b.get("pendientes", []):
            pid = p["peticion_id"]
            if pid in vistos:
                continue

            # ¿hay que reclamarla primero? (mensaje "a la persona", instancia activa)
            if p.get("reclamable") and "." in ident["id"]:
                r = reclamar(pid, ident)
                if "error" in r or "error_http" in r:
                    print(f"  [reclamar {pid}] no se pudo (probablemente otra instancia ya la cogio): {r}")
                    vistos.add(pid)
                    continue

            vistos.add(pid)
            decision, motivo = politica.evaluar(p["accion"], p["params"])

            if decision == "denegar":
                decidir(pid, "rechazar", motivo, ident)
                print(f"\n--- PETICION {pid} de {p['de']} ---\n"
                      f"  accion: {p['accion']}  params: {p['params']}\n"
                      f"  -> RECHAZADA SOLA (politica): {motivo}")
                continue

            if decision == "permitir":
                decidir(pid, "autorizar", None, ident)
                res = _ejecutar_accion(p["accion"], p["params"])
                poner_resultado(pid, res, ident)
                print(f"\n--- PETICION {pid} de {p['de']} ---\n"
                      f"  accion: {p['accion']}  params: {p['params']}\n"
                      f"  -> AUTORIZADA Y EJECUTADA SOLA (politica: {motivo}). Resultado: {res}")
                continue

            # 'preguntar': avisa y deja el pid en espera. NO bloquea el bucle.
            notificar.avisar_peticion({"peticion_id": pid, "de": p["de"],
                                        "accion": p["accion"], "params": p["params"]})
            en_espera_humana[pid] = p
            print(f"\n--- PETICION {pid} de {p['de']} ---\n"
                  f"  accion: {p['accion']}  params: {p['params']}\n"
                  f"  -> esperando decision humana (boton Telegram, o a mano:\n"
                  f"     python cliente.py autorizar {pid}\n"
                  f"     python cliente.py rechazar {pid} --motivo \"...\")")

        # revisa las que estan en espera de decision humana externa
        for pid in list(en_espera_humana.keys()):
            p = en_espera_humana[pid]
            e = estado(pid, ident)
            est = e.get("estado")
            if est == "AUTORIZADA":
                res = _ejecutar_accion(p["accion"], p["params"])
                poner_resultado(pid, res, ident)
                print(f"  -> {pid} AUTORIZADA (humano) y EJECUTADA. Resultado: {res}")
                del en_espera_humana[pid]
            elif est == "RECHAZADA":
                print(f"  -> {pid} RECHAZADA (humano): {e.get('motivo')}")
                del en_espera_humana[pid]
            # si sigue PENDIENTE, se revisa en la proxima vuelta

        time.sleep(intervalo)


# --------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="IA2IA cliente v0.2")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generar-identidad")
    g.add_argument("--nombre", required=True)
    g.add_argument("--forzar", action="store_true")

    ci = sub.add_parser("crear-instancia")
    ci.add_argument("--sufijo", required=True)
    ci.add_argument("--forzar", action="store_true")

    aa = sub.add_parser("agenda-anadir")
    aa.add_argument("--nombre", required=True)
    aa.add_argument("--clave-publica", required=True)
    aa.add_argument("--reemplazar", action="store_true",
                     help="si el nombre ya existe con otra clave, sustituirla "
                          "(caso legitimo: la clave se regenero)")

    sub.add_parser("bandeja")
    e = sub.add_parser("enviar")
    e.add_argument("--to", required=True); e.add_argument("--accion", required=True)
    e.add_argument("--params", default="{}")
    rc = sub.add_parser("reclamar"); rc.add_argument("peticion_id")
    a = sub.add_parser("autorizar"); a.add_argument("peticion_id")
    r = sub.add_parser("rechazar"); r.add_argument("peticion_id"); r.add_argument("--motivo")
    s = sub.add_parser("estado"); s.add_argument("peticion_id")
    sub.add_parser("avisos")
    bl = sub.add_parser("bloquear"); bl.add_argument("id")
    db_ = sub.add_parser("desbloquear"); db_.add_argument("id")
    sub.add_parser("servir")
    args = ap.parse_args()

    if args.cmd == "generar-identidad":
        if os.path.exists(RUTA_MI_IDENTIDAD) and not args.forzar:
            sys.exit(f"[!] {RUTA_MI_IDENTIDAD} ya existe. Usa --forzar para sobrescribir "
                     f"(pierdes la identidad anterior: cambia tu id).")
        ident = identidad.generar_identidad(args.nombre)
        ident["relay"] = "http://127.0.0.1:8790"
        with open(RUTA_MI_IDENTIDAD, "w", encoding="utf-8") as f:
            json.dump(ident, f, ensure_ascii=False, indent=2)
        print(f"Identidad creada. Tu id: {ident['id']}")
        print(f"Tu clave PUBLICA (comparte esta, nunca la privada):\n  {ident['clave_publica']}")

    elif args.cmd == "crear-instancia":
        if os.path.exists(RUTA_MI_INSTANCIA) and not args.forzar:
            sys.exit(f"[!] {RUTA_MI_INSTANCIA} ya existe. Usa --forzar para sobrescribir.")
        raiz = identidad_raiz()
        inst = identidad.generar_instancia(raiz, args.sufijo)
        with open(RUTA_MI_INSTANCIA, "w", encoding="utf-8") as f:
            json.dump(inst, f, ensure_ascii=False, indent=2)
        print(f"Instancia creada: {inst['id']}")

    elif args.cmd == "agenda-anadir":
        try:
            idv = agenda.anadir(args.nombre, args.clave_publica, reemplazar=args.reemplazar)
            print(f"Anadido a la agenda: {args.nombre} -> {idv}")
        except agenda.AgendaError as e:
            print(json.dumps({"error": str(e)}, ensure_ascii=False, indent=2))
            sys.exit(1)

    elif args.cmd == "bandeja":
        print(json.dumps(bandeja(), ensure_ascii=False, indent=2))

    elif args.cmd == "enviar":
        try:
            contacto = agenda.resolver(args.to)
        except agenda.AgendaError as e:
            print(json.dumps({"error": str(e)}, ensure_ascii=False, indent=2))
            sys.exit(1)
        destino = contacto["id"] if contacto else args.to
        print(json.dumps(enviar(destino, args.accion, json.loads(args.params)),
                         ensure_ascii=False, indent=2))

    elif args.cmd == "reclamar":
        print(json.dumps(reclamar(args.peticion_id), ensure_ascii=False, indent=2))
    elif args.cmd == "autorizar":
        print(json.dumps(decidir(args.peticion_id, "autorizar"), ensure_ascii=False, indent=2))
    elif args.cmd == "rechazar":
        print(json.dumps(decidir(args.peticion_id, "rechazar", args.motivo),
                         ensure_ascii=False, indent=2))
    elif args.cmd == "estado":
        print(json.dumps(estado(args.peticion_id), ensure_ascii=False, indent=2))
    elif args.cmd == "avisos":
        print(json.dumps(avisos(), ensure_ascii=False, indent=2))
    elif args.cmd == "bloquear":
        print(json.dumps(bloquear(args.id), ensure_ascii=False, indent=2))
    elif args.cmd == "desbloquear":
        print(json.dumps(desbloquear(args.id), ensure_ascii=False, indent=2))
    elif args.cmd == "servir":
        servir()


if __name__ == "__main__":
    main()
