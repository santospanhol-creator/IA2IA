# -*- coding: utf-8 -*-
"""
IA2IA identidad.py — identidad criptografica (Ed25519), v0.2.

Cada participante (persona o instancia) tiene un par de claves Ed25519.
El ID es la huella (sha256) de la clave publica: nadie reparte numeros,
no hay autoridad central, y el relay verifica sin conocer secretos de
nadie — todo lo que hace falta viaja en la propia peticion (clave publica
+ firma). Sustituye al secreto HMAC compartido de v0.1.

Identidad de INSTANCIA: una persona (identidad "raiz") puede abrir varias
instancias (varias maquinas/Claudes). Cada instancia tiene SU PROPIO par
de claves y un CERTIFICADO firmado por la clave privada de la raiz que
dice "esta clave publica de instancia actua en nombre de mi raiz, bajo
este id". El id de instancia es "<id_raiz>.<sufijo>" (sufijo elegido
localmente, p.ej. el nombre de maquina). Quien verifica NO necesita
contactar a nadie: valida la firma del certificado con la clave publica
de la raiz (cuyo hash ya es el id_raiz que va en el propio id).

Dependencia: `cryptography` (PyCA) — Ed25519, estandar, ya instalada.
La clave PRIVADA nunca sale de mi_identidad.json / mi_instancia.json
(ambos gitignored). La clave PUBLICA se comparte sin problema.
"""
import time
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

LONGITUD_ID = 64  # hex chars = 256 bits (sha256 COMPLETO, sin truncar).
                   # Subido desde 16 hex (64 bits) el 2026-09-16 tras revision de
                   # seguridad-informatica (parte 2026-09-16-1730, hallazgo H1):
                   # 64 bits es poco frente a un ataque de segunda-preimagen con
                   # hardware dedicado y permitiria suplantar un id (a Santos o a
                   # Abraham). Nadie tenia identidades emitidas todavia, asi que
                   # no hay compatibilidad que romper. El formato "<raiz>.<sufijo>"
                   # no cambia, como preveia el comentario original.


def _pub_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def huella(clave_publica_hex: str) -> str:
    """ID = sha256(clave publica) completo (LONGITUD_ID hex chars = 256 bits)."""
    return hashlib.sha256(bytes.fromhex(clave_publica_hex)).hexdigest()[:LONGITUD_ID]


def generar_par():
    """Nuevo par de claves Ed25519. Devuelve (clave_privada_hex, clave_publica_hex)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_hex = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex()
    pub_hex = _pub_bytes(pub).hex()
    return priv_hex, pub_hex


def generar_identidad(nombre: str) -> dict:
    """Identidad RAIZ nueva (persona). Para guardar en mi_identidad.json."""
    priv_hex, pub_hex = generar_par()
    return {"nombre": nombre, "id": huella(pub_hex),
            "clave_privada": priv_hex, "clave_publica": pub_hex}


def firmar(clave_privada_hex: str, mensaje: bytes) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(clave_privada_hex))
    return priv.sign(mensaje).hex()


def verificar(clave_publica_hex: str, mensaje: bytes, firma_hex: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(clave_publica_hex))
        pub.verify(bytes.fromhex(firma_hex), mensaje)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------- instancias

def _cert_base(instancia_id, instancia_pubkey_hex, raiz_id, creado) -> bytes:
    return (f"IA2IA-CERT\n{instancia_id}\n{instancia_pubkey_hex}\n"
            f"{raiz_id}\n{creado}").encode("utf-8")


def generar_instancia(identidad_raiz: dict, sufijo: str) -> dict:
    """Crea un par de claves nuevo para una instancia y lo certifica con la
    clave privada de la raiz. `identidad_raiz` es el dict de mi_identidad.json
    de la PERSONA (necesita su clave_privada para firmar el certificado)."""
    sufijo = (sufijo or "").strip()
    if not sufijo or "." in sufijo:
        raise ValueError("el sufijo de instancia no puede ir vacio ni llevar '.'")
    raiz_id = identidad_raiz["id"]
    instancia_id = f"{raiz_id}.{sufijo}"
    priv_hex, pub_hex = generar_par()
    creado = int(time.time())
    firma_raiz = firmar(identidad_raiz["clave_privada"],
                         _cert_base(instancia_id, pub_hex, raiz_id, creado))
    cert = {"instancia_id": instancia_id, "instancia_pubkey": pub_hex,
            "raiz_id": raiz_id, "raiz_pubkey": identidad_raiz["clave_publica"],
            "creado": creado, "firma_raiz": firma_raiz}
    return {"nombre": f"{identidad_raiz.get('nombre', '?')} ({sufijo})",
            "id": instancia_id, "clave_privada": priv_hex, "clave_publica": pub_hex,
            "cert": cert}


def verificar_cert(cert: dict):
    """Valida un certificado de instancia de forma autonoma (sin red).
    Devuelve (ok: bool, error: str|None)."""
    try:
        raiz_id = cert["raiz_id"]
        instancia_id = cert["instancia_id"]
        if huella(cert["raiz_pubkey"]) != raiz_id:
            return False, "raiz_pubkey no coincide con raiz_id (hash)"
        if not instancia_id.startswith(raiz_id + "."):
            return False, "instancia_id no cuelga de raiz_id"
        base = _cert_base(instancia_id, cert["instancia_pubkey"], raiz_id, cert["creado"])
        if not verificar(cert["raiz_pubkey"], base, cert["firma_raiz"]):
            return False, "firma del certificado invalida"
        return True, None
    except (KeyError, TypeError, ValueError) as e:
        return False, f"certificado mal formado: {e}"
