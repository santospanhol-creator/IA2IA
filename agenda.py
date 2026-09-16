# -*- coding: utf-8 -*-
"""
IA2IA agenda.py — directorio "nombre bonito -> clave publica / id".

Solo contiene claves PUBLICAS: puede vivir en el repo (publico) o
intercambiarse sin cuidado especial. La clave PRIVADA nunca esta aqui.

Como el movil: ves "Santos", el numero unico es su id (huella de la
clave publica). Un nombre = un contacto: `anadir()` no deja dos ids con el
mismo nombre en silencio (ver NombreDuplicadoError/reemplazar), y
`resolver()` nunca elige el primero en silencio si el nombre es ambiguo
(ver NombreAmbiguoError) — esto ultimo cubre tambien un agenda.json
heredado que ya trajera duplicados de antes de esta regla.
"""
import os
import json

AQUI = os.path.dirname(os.path.abspath(__file__))
RUTA = os.path.join(AQUI, "agenda.json")
RUTA_EJEMPLO = os.path.join(AQUI, "agenda.example.json")


class AgendaError(Exception):
    """Base de los conflictos de identidad de la agenda: nombre duplicado
    con clave distinta, o nombre ambiguo (varios contactos lo comparten)."""


class NombreDuplicadoError(AgendaError):
    """Ya existe un contacto con ese nombre pero OTRO id (otra clave publica)."""


class NombreAmbiguoError(AgendaError):
    """El nombre casa con mas de un contacto (agenda.json heredado con
    duplicados): no se puede elegir uno en silencio."""


def _ruta_activa(ruta=None):
    if ruta:
        return ruta
    return RUTA if os.path.exists(RUTA) else RUTA_EJEMPLO


def cargar(ruta=None) -> dict:
    """id -> {id, nombre, clave_publica}"""
    ruta = _ruta_activa(ruta)
    if not os.path.exists(ruta):
        return {}
    with open(ruta, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {c["id"]: c for c in data.get("contactos", [])}


def resolver(nombre_o_id: str, ruta=None):
    """Acepta un id (o id.instancia) directo, o un nombre de la agenda.
    Si es id.instancia de alguien conocido por su raiz, devuelve el contacto
    con el id de instancia sustituido (la clave publica de la raiz no sirve
    para verificar la instancia — eso lo hace el certificado que viaja en
    la propia peticion, esto es solo para resolver nombres)."""
    contactos = cargar(ruta)
    if nombre_o_id in contactos:
        return contactos[nombre_o_id]
    raiz = nombre_o_id.split(".", 1)[0]
    if raiz in contactos and raiz != nombre_o_id:
        c = dict(contactos[raiz])
        c["id"] = nombre_o_id
        return c
    # defensa en profundidad: si un agenda.json heredado ya trae el mismo
    # nombre en mas de un contacto, NUNCA se devuelve el primero en silencio
    # (eso es "hablar con quien no tocaba" sin enterarse) - se avisa.
    coincidencias = [c for c in contactos.values()
                      if c.get("nombre", "").lower() == nombre_o_id.lower()]
    if len(coincidencias) > 1:
        ids = ", ".join(c["id"] for c in coincidencias)
        raise NombreAmbiguoError(
            f"'{nombre_o_id}' coincide con {len(coincidencias)} contactos de la agenda "
            f"({ids}); resuelve por id directo o depura agenda.json"
        )
    if coincidencias:
        return coincidencias[0]
    return None


def anadir(nombre: str, clave_publica_hex: str, ruta=None, reemplazar: bool = False) -> str:
    """Da de alta/actualiza un contacto por su clave publica. Devuelve su id.

    Modelo "un nombre = un contacto", como en el movil: si `nombre` ya esta
    en la agenda apuntando a OTRO id (otra clave publica), no se crea una
    segunda entrada en silencio - se rechaza con NombreDuplicadoError, salvo
    que se pida `reemplazar=True` (caso legitimo: la clave se regenero).
    Anadir el mismo nombre con la MISMA clave (mismo id) es idempotente.
    """
    from identidad import huella
    ruta = ruta or RUTA
    existentes = list(cargar(ruta).values()) if os.path.exists(ruta) else []
    idv = huella(clave_publica_hex)

    colisiones = [c for c in existentes
                  if c.get("nombre", "").lower() == nombre.lower() and c["id"] != idv]
    if colisiones and not reemplazar:
        otros = ", ".join(c["id"] for c in colisiones)
        raise NombreDuplicadoError(
            f"ya existe '{nombre}' en la agenda con otra clave (id {otros}); "
            f"pasa reemplazar=True si la clave se regenero, o usa otro nombre"
        )

    existentes = [c for c in existentes if c["id"] != idv]
    if reemplazar:
        existentes = [c for c in existentes if c.get("nombre", "").lower() != nombre.lower()]
    existentes.append({"id": idv, "nombre": nombre, "clave_publica": clave_publica_hex})
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump({"contactos": existentes}, f, ensure_ascii=False, indent=2)
    return idv
