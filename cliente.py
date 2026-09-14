# -*- coding: utf-8 -*-
"""
IA2IA cliente/CLI v0.1 — lo usan AMBOS lados (Santos y Abraham).

Firma cada llamada con tu HMAC y habla con el relay. Incluye el gate humano:
para autorizar/rechazar peticiones que te llegan.

Config de TU identidad (mi_identidad.json junto a este fichero):
    {"id": "34-1001", "secret": "...", "relay": "http://IP_DEL_RELAY:8790"}

Comandos:
    python cliente.py bandeja
    python cliente.py enviar --to 34-2001 --accion dame_saldo --params '{"cif":"B123"}'
    python cliente.py autorizar <peticion_id>
    python cliente.py rechazar  <peticion_id> --motivo "no procede"
    python cliente.py estado    <peticion_id>
    python cliente.py servir            # bucle: muestra pendientes y, al autorizar, ejecuta
"""
import os
import sys
import json
import time
import hmac
import hashlib
import argparse
import urllib.request

AQUI = os.path.dirname(os.path.abspath(__file__))


def cfg():
    with open(os.path.join(AQUI, "mi_identidad.json"), "r", encoding="utf-8") as f:
        c = json.load(f)
    c["relay"] = os.environ.get("IA2IA_RELAY", c.get("relay", "http://127.0.0.1:8790"))
    return c


def _firma(secret, ident, ts, metodo, path, body):
    base = f"{ident}\n{ts}\n{metodo}\n{path}\n{body}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()


def _llamar(metodo, path, body_obj=None):
    c = cfg()
    body = json.dumps(body_obj, ensure_ascii=False) if body_obj is not None else ""
    ts = str(int(time.time()))
    sig = _firma(c["secret"], c["id"], ts, metodo, path, body)
    req = urllib.request.Request(
        c["relay"] + path, method=metodo,
        data=body.encode("utf-8") if body else None,
        headers={"Content-Type": "application/json",
                 "X-IA2IA-Id": c["id"], "X-IA2IA-Ts": ts, "X-IA2IA-Sig": sig})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"error_http": e.code, "detalle": e.read().decode("utf-8", "replace")}


# --- API de alto nivel ---
def enviar(to, accion, params):
    return _llamar("POST", "/peticion", {"to": to, "accion": accion, "params": params})

def bandeja():
    return _llamar("GET", f"/bandeja?to={cfg()['id']}")

def decidir(pid, decision, motivo=None):
    return _llamar("POST", "/decidir", {"peticion_id": pid, "decision": decision, "motivo": motivo})

def poner_resultado(pid, resultado):
    return _llamar("POST", "/resultado", {"peticion_id": pid, "resultado": resultado})

def estado(pid):
    return _llamar("GET", f"/estado?peticion_id={pid}")


# --- Ejecutores locales: mapea accion -> funcion tuya (aqui defines lo que TU IA hace) ---
def _ejecutar_accion(accion, params):
    # DEMO. Sustituye por tus funciones reales de negocio.
    if accion == "ping":
        return {"pong": True, "eco": params}
    return {"aviso": f"accion '{accion}' no implementada en este lado", "params": params}


def servir(intervalo=5):
    """Bucle: muestra peticiones PENDIENTES. El humano autoriza/rechaza; al autorizar,
    ejecuta la accion localmente y publica el resultado."""
    print(f"[servir] escuchando bandeja de {cfg()['id']} (Ctrl+C para salir)")
    vistos = set()
    while True:
        b = bandeja()
        for p in b.get("pendientes", []):
            pid = p["peticion_id"]
            if pid in vistos:
                continue
            vistos.add(pid)
            print(f"\n--- PETICION {pid} ---")
            print(f"  de: {p['de']}  accion: {p['accion']}  params: {p['params']}")
            resp = input("  autorizar? [s/N]: ").strip().lower()
            if resp == "s":
                decidir(pid, "autorizar")
                res = _ejecutar_accion(p["accion"], p["params"])
                poner_resultado(pid, res)
                print(f"  -> AUTORIZADA y EJECUTADA. Resultado: {res}")
            else:
                motivo = input("  motivo del rechazo: ").strip()
                decidir(pid, "rechazar", motivo or None)
                print("  -> RECHAZADA")
        time.sleep(intervalo)


def main():
    ap = argparse.ArgumentParser(description="IA2IA cliente")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("bandeja")
    e = sub.add_parser("enviar"); e.add_argument("--to", required=True)
    e.add_argument("--accion", required=True); e.add_argument("--params", default="{}")
    a = sub.add_parser("autorizar"); a.add_argument("peticion_id")
    r = sub.add_parser("rechazar"); r.add_argument("peticion_id"); r.add_argument("--motivo")
    s = sub.add_parser("estado"); s.add_argument("peticion_id")
    sub.add_parser("servir")
    args = ap.parse_args()

    if args.cmd == "bandeja":
        print(json.dumps(bandeja(), ensure_ascii=False, indent=2))
    elif args.cmd == "enviar":
        print(json.dumps(enviar(args.to, args.accion, json.loads(args.params)),
                         ensure_ascii=False, indent=2))
    elif args.cmd == "autorizar":
        print(json.dumps(decidir(args.peticion_id, "autorizar"), ensure_ascii=False, indent=2))
    elif args.cmd == "rechazar":
        print(json.dumps(decidir(args.peticion_id, "rechazar", args.motivo),
                         ensure_ascii=False, indent=2))
    elif args.cmd == "estado":
        print(json.dumps(estado(args.peticion_id), ensure_ascii=False, indent=2))
    elif args.cmd == "servir":
        servir()


if __name__ == "__main__":
    main()
