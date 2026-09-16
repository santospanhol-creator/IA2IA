# -*- coding: utf-8 -*-
"""
IA2IA notificar.py — popup al humano (protocolo-v0.2.md S7).

El "popup" real (boton Aprobar/Rechazar) vive en la infraestructura ya
existente: bot de Telegram + panel de Mision Control (mismo TELEGRAM_BOT_TOKEN
que usa panel/server.js). Este modulo NO reimplementa ese bot: manda el aviso
por Telegram con DOS BOTONES INLINE [Autorizar] [Rechazar] (callback_data
"ia2ia|autorizar|<pid>" / "ia2ia|rechazar|<pid>"). Al pulsar, panel/server.js
(mismo bot, mismo evento callback_query) lanza `cliente.py autorizar/
rechazar <pid>` como proceso suelto -> POST /decidir al relay -> el bucle de
`cliente.py servir` recoge la decision en su siguiente vuelta y ejecuta.

Si no hay TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID en el entorno o falla el
envio, no revienta nada: solo se queda en el log de consola. El gate
humano real (S6, "todo proceso invisible") sigue funcionando por CLI
(`cliente.py autorizar/rechazar <pid>` a mano) aunque Telegram falle.

Aislamiento para pruebas: despejar TELEGRAM_BOT_TOKEN/TELEGRAM_*CHAT_ID
del entorno NO basta — `_valor()` cae a leer los .env REALES del disco
(vease _ENVS) y puede acabar mandando un aviso real de todas formas (asi
paso un popup de prueba real a Telegram el 2026-09-16). La via OFICIAL
para probar `servir()`/`avisar_peticion()` sin riesgo de aviso real es
poner `IA2IA_NOTIFICAR_DESACTIVAR` (cualquier valor no vacio) en el
entorno: `avisar_telegram()` devuelve False de inmediato, sin abrir
ningun .env ni tocar la red. El log local (`_print_seguro`) sigue
saliendo igual: el gate humano por consola no se ve afectado.
"""
import os
import sys
import json
import urllib.request
import urllib.error

AQUI = os.path.dirname(os.path.abspath(__file__))
_RAIZ_HERMES = os.path.dirname(AQUI)  # C:\hermes

# Candidatos de .env, EN ORDEN: el primero que defina la clave gana. El boton
# solo sirve si el aviso sale del MISMO bot que escucha panel/server.js para
# callback_query (constante DATAROOTS_BOT_ENV ahi): C:\hermes\.env si define
# TELEGRAM_BOT_TOKEN, si no C:\N8N_Bot_DataRoots\.env (legado, mismo bot real).
# Usar un bot distinto mandaria el aviso a un chat cuyos clics nadie escucha.
_ENVS = [
    os.path.join(AQUI, ".env"),                 # override propio de ia2ia, si existiera
    os.path.join(_RAIZ_HERMES, ".env"),
    "C:\\N8N_Bot_DataRoots\\.env",
]

try:
    from dotenv import dotenv_values
except ImportError:
    dotenv_values = None


def _valor(*claves) -> str:
    for k in claves:
        if os.environ.get(k):
            return os.environ[k]
    if dotenv_values:
        for ruta in _ENVS:
            if not os.path.exists(ruta):
                continue
            vals = dotenv_values(ruta)
            for k in claves:
                if vals.get(k):
                    return vals[k]
    return None


def _credenciales():
    # IA2IA_TELEGRAM_* como alternativa si este lado quiere un bot/chat propio
    # distinto del resto de HERMES; si no esta, cae en el bot/chat de la casa.
    token = _valor("IA2IA_TELEGRAM_BOT_TOKEN", "TELEGRAM_BOT_TOKEN")
    chat_id = _valor("IA2IA_TELEGRAM_CHAT_ID", "TELEGRAM_SANTOS_CHAT_ID", "TELEGRAM_CHAT_ID")
    return token, chat_id


def avisar_telegram(mensaje: str, teclado: dict = None) -> bool:
    if os.environ.get("IA2IA_NOTIFICAR_DESACTIVAR"):
        # kill-switch: ni _credenciales() ni _valor() se llaman, asi que no
        # se abre ningun .env del disco y no hay llamada de red posible.
        return False
    token, chat_id = _credenciales()
    if not (token and chat_id):
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": mensaje}
    if teclado:
        payload["reply_markup"] = teclado
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return False


def _print_seguro(texto: str):
    """print() normal, pero SIN reventar si la consola del proceso (p.ej. un
    servicio de fondo lanzado sin consola UTF-8 real, cp1252 en Windows) no
    sabe codificar un emoji. Nunca debe tumbar `cliente.py servir` por un
    fallo de encoding en el log — el aviso real (Telegram) ya salio o lo
    intentara aparte."""
    try:
        print(texto)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        print(texto.encode(enc, errors="replace").decode(enc, errors="replace"))


def avisar_peticion(peticion: dict):
    """peticion: {peticion_id, de, accion, params}. Log en consola SIEMPRE,
    Telegram con botones Autorizar/Rechazar si hay credenciales (best-effort,
    nunca bloqueante). Muestra quien pide, que accion y sus parametros
    (las "consecuencias" que pide el protocolo S7) antes de decidir."""
    pid = peticion["peticion_id"]
    params_txt = json.dumps(peticion.get("params", {}), ensure_ascii=False)
    txt = (f"🔔 IA2IA — decision pendiente\n\n"
           f"Quien pide: {peticion['de']}\n"
           f"Accion: {peticion['accion']}\n"
           f"Parametros: {params_txt}\n\n"
           f"¿Autorizar esta accion? Si no decides, la peticion sigue en espera.\n"
           f"Tambien por CLI: python cliente.py autorizar {pid}  /  rechazar {pid}")
    _print_seguro(f"\n[popup] {txt}\n")
    teclado = {"inline_keyboard": [[
        {"text": "✅ Autorizar", "callback_data": f"ia2ia|autorizar|{pid}"},
        {"text": "❌ Rechazar", "callback_data": f"ia2ia|rechazar|{pid}"},
    ]]}
    avisar_telegram(txt, teclado)
