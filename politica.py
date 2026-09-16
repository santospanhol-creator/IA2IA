# -*- coding: utf-8 -*-
"""
IA2IA politica.py — motor de permisos por participante (v0.2, S5 del
protocolo). Cada lado declara que SE le puede pedir y que NO, y lo aplica
SU LADO (cliente.py) antes de molestar al humano.

- denylist: SIEMPRE gana. Si una peticion encaja, se RECHAZA sola, sin
  popup (credenciales, cuentas/datos bancarios, pagos... y lo que anada
  cada participante). Doble candado: ademas de esto, la IA no debe manejar
  contrasenas ni cuentas bancarias por diseno, pase lo que pase aqui.
- allowlist: se autoriza y ejecuta sola (con aviso informativo al humano,
  nunca en silencio).
- ni una cosa ni otra: se pregunta al humano (popup).

Nunca se decide un "else" que ejecute o rechace por defecto sin marcarlo:
toda peticion que no cae en denylist ni en allowlist es SIEMPRE
'preguntar', nunca se cuela como permitida.
"""
import os
import json
import re

AQUI = os.path.dirname(os.path.abspath(__file__))
RUTA = os.path.join(AQUI, "politica.json")
RUTA_EJEMPLO = os.path.join(AQUI, "politica.example.json")

# Denylist de casa: se suma SIEMPRE a la de cada participante, no se puede
# quitar editando politica.json (defensa en profundidad, ver protocolo S5).
DENYLIST_BASE = [
    r"contrase", r"password", r"credencial", r"secreto",
    r"token", r"api[_-]?key", r"clave.?privada",
    r"cuenta.?banc", r"\biban\b", r"tarjeta", r"\bcvv\b",
    r"transferenc", r"\bpago\b", r"\bcobro\b",
]


def _ruta_activa(ruta=None):
    if ruta:
        return ruta
    return RUTA if os.path.exists(RUTA) else RUTA_EJEMPLO


def cargar(ruta=None) -> dict:
    ruta = _ruta_activa(ruta)
    propia = {"denylist": [], "allowlist": []}
    if os.path.exists(ruta):
        with open(ruta, "r", encoding="utf-8") as f:
            data = json.load(f)
        propia["denylist"] = data.get("denylist", [])
        propia["allowlist"] = data.get("allowlist", [])
    return {"denylist": DENYLIST_BASE + propia["denylist"],
            "allowlist": propia["allowlist"]}


def _texto(accion: str, params: dict) -> str:
    return (accion + " " + json.dumps(params, ensure_ascii=False)).lower()


def evaluar(accion: str, params: dict, ruta=None):
    """Devuelve (decision, motivo). decision in {'denegar','permitir','preguntar'}.
    denylist siempre gana sobre allowlist si una peticion encajara en ambas."""
    pol = cargar(ruta)
    texto = _texto(accion, params or {})
    for patron in pol["denylist"]:
        if re.search(patron, texto, re.IGNORECASE):
            return "denegar", f"categoria prohibida por politica (coincide con '{patron}')"
    for patron in pol["allowlist"]:
        if re.search(patron, texto, re.IGNORECASE):
            return "permitir", f"accion en allowlist (coincide con '{patron}')"
    return "preguntar", "no esta en denylist ni en allowlist: decide el humano"
