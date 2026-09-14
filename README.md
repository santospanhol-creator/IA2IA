# IA2IA — Comunicación entre IAs / usuarios

Protocolo mínimo para que **dos personas (y sus IAs) que están en máquinas distintas**
se pidan cosas por internet, con **autorización humana** antes de ejecutar nada.

Pensado para probarlo entre **las IAs de Santos** y **las de Abraham**.

```
  Santos (34-1001)  →  pide algo  →  [ RELAY ]  →  Abraham (34-2001)
                                                     │
                                          un humano/IA decide:
                                          AUTORIZAR → ejecuta → devuelve resultado
                                          RECHAZAR  → motivo
  Santos  ←  recibe estado + resultado  ←  [ RELAY ]  ←──────────┘
```

Idea clave: **el relay NO ejecuta nada**. Solo transporta. Cada lado ejecuta en SU
máquina lo que su dueño autoriza. El "poder" no se cede: se pide y se concede caso a caso.

## Piezas
| Fichero | Qué es | Dónde corre |
|---|---|---|
| `protocolo.md` | La especificación (ids, firma, estados, endpoints). | — |
| `relay.py` | Servidor central. Enruta y guarda estados (sqlite). No ejecuta acciones. | **Una** máquina con IP/dominio público (o un túnel). |
| `cliente.py` | Librería + CLI. Enviar peticiones, ver bandeja, autorizar/rechazar, ejecutar. | En **cada** lado (Santos y Abraham). |
| `identidades.json` | Ids + secretos de todos los participantes. | **Solo** en el relay. |
| `mi_identidad.json` | Tu id + tu secreto + URL del relay. | En **tu** lado. |

## Identidades (números inequívocos)
Formato `PP-NNNN` (país-secuencia). Tu "número de teléfono" entre IAs:
- `34-1001` → HERMES-Santos
- `34-2001` → HERMES-Abraham

Cada uno tiene un **secreto HMAC**: firma cada llamada para que el relay sepa que eres tú
y nadie pueda suplantarte ni reenviar una llamada vieja (ventana anti-replay de 300 s).

## Puesta en marcha (prueba local)
```bash
# 1) En el relay:
cp identidades.example.json identidades.json     # y cambia los secretos
python relay.py                                   # escucha en :8790

# 2) En el lado de Santos (34-1001):
cp mi_identidad.example.json mi_identidad.json    # id=34-1001, secret y relay reales
python cliente.py enviar --to 34-2001 --accion ping --params '{"hola":"abraham"}'

# 3) En el lado de Abraham (34-2001):
cp mi_identidad.example.json mi_identidad.json    # id=34-2001, su secret, mismo relay
python cliente.py servir     # ve la petición, la AUTORIZA a mano, se ejecuta y responde

# 4) Santos consulta el resultado:
python cliente.py estado <peticion_id>
```

## Cómo conecta cada IA sus acciones reales
En `cliente.py`, la función `_ejecutar_accion(accion, params)` es el punto donde **cada
dueño** engancha lo que su IA sabe hacer (consultar su CRM, su SQL, lanzar un flujo…).
Por defecto solo trae `ping`. Nada se ejecuta hasta que el humano de ese lado autoriza en
`servir`. Así el gate humano queda **antes** de tocar sistemas reales.

## Seguridad
- Secretos **solo** en `identidades.json` / `mi_identidad.json` (ambos **ignorados por git**).
- En producción: relay tras **HTTPS**, rotar secretos, y guardar auditoría de quién pidió/autorizó qué.
- La autorización humana es deliberada: es lo que impide que una IA ejecute algo en el
  sistema de otra sin que una persona lo apruebe.

## Relación con estándares
Es un esqueleto propio y minimalista. El patrón (identidad + petición + autorización +
ejecución local) es afín a lo que persiguen estándares emergentes de interoperabilidad
entre agentes (p.ej. A2A) y complementario a MCP (que conecta herramientas a UN modelo).
Cuando esos maduren, este relay puede envolverse o sustituirse sin cambiar el patrón.

## Estado
v0.1 — esqueleto funcional para la prueba Santos↔Abraham. Repo privado.
