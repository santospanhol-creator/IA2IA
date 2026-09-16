# IA2IA — Comunicación entre IAs / usuarios (v0.2)

Protocolo para que **dos personas (y sus IAs) que están en máquinas distintas** se pidan
cosas por internet, con **identidad criptográfica** y **autorización humana** antes de
ejecutar nada. Ver la especificación completa en `protocolo-v0.2.md` (v0.1 queda en
`protocolo.md` como referencia histórica).

```
  A            firma con su clave privada           [ RELAY ]          B
  │  --------------------------------------------------->  │            │
  │        (el relay verifica con la clave publica          │            │
  │         que A adjunta; no guarda secretos de nadie)     │            │
  │                                                          │--------->│
  │                                          politica de B: denylist -> rechazo solo
  │                                                       ni deny ni allow -> POPUP a B
  │                                          B decide: AUTORIZAR -> ejecuta -> resultado
  │  <-------------------------------------------------------------------│
```

**Idea clave (sin cambios desde v0.1): el relay NO ejecuta nada.** Solo transporta y
aplica las reglas. Cada lado ejecuta en SU máquina lo que su dueño autoriza.

## Qué cambia en v0.2 frente a v0.1

| | v0.1 | v0.2 |
|---|---|---|
| Identidad | secreto HMAC compartido, repartido a mano | **par de claves Ed25519**; tu id es el hash de tu clave pública |
| Registro central | `identidades.json` con TODOS los secretos, solo en el relay | **no hace falta**: cada petición trae su propia clave pública (autocertificado) |
| Varias máquinas por persona | no existía | **identidad por instancia** (`<id_raiz>.<sufijo>`), con certificado firmado por la raíz |
| Mensaje "a la persona" | no existía | **candado de reclamación atómico**: solo una instancia se queda con él |
| Directorio de nombres | no existía | `agenda.json` (nombre → clave pública, puede ser público) |
| Permisos | no existía | `politica.json` por lado: denylist (auto-rechazo) / allowlist (auto-autoriza) / resto → pregunta al humano |
| Anti-abuso | no existía | 1 peticion/hora salvo interacción humana, máx. 5 pendientes, sin auto-reintento (con escalado), bloqueo por id, tope de tamaño/hora, **allowlist de root-ids** y **tope de tamaño de cuerpo (413)** — todo **en el relay** |

## Piezas

| Fichero | Qué es | Dónde vive |
|---|---|---|
| `protocolo-v0.2.md` | La especificación. | — |
| `identidad.py` | Claves Ed25519, id = huella de la clave pública, certificados de instancia. | En cada lado (lo importan `cliente.py` y `relay.py`). |
| `relay.py` | Servidor central. Verifica firmas (autocertificado, sin secretos compartidos), aplica el candado de reclamación y las reglas anti-abuso, guarda auditoría (sqlite). NO ejecuta acciones. | **Una** máquina con IP/dominio (o un túnel). |
| `cliente.py` | Librería + CLI: identidad, agenda, política, enviar/reclamar/decidir/resultado, el bucle `servir` (gate humano). | En **cada** lado. |
| `agenda.py` / `agenda.example.json` | Directorio nombre → clave pública. Solo claves PÚBLICAS: puede ser público. | En cada lado (o compartido). |
| `politica.py` / `politica.example.json` | Motor de permisos: qué se autoriza solo, qué se rechaza solo, qué pregunta. | En cada lado (`politica.json` es local, no secreto pero personal). |
| `notificar.py` | Aviso del popup: log en consola siempre, Telegram si hay credenciales en `.env`. | En cada lado. |
| `mi_identidad.json` | **Tu** identidad raíz (clave privada + pública + tu id). | **Solo tu lado.** Gitignored. |
| `mi_instancia.json` | Identidad de **esta** máquina/instancia (opcional). | **Solo tu lado.** Gitignored. |
| `test_ia2ia.py` | Pruebas de punta a punta (ver más abajo). | — |

## Instalación (un tercero, p. ej. Abraham)

```bash
git clone https://github.com/santospanhol-creator/IA2IA.git
cd IA2IA
python -m venv .venv
# Windows:
.venv\Scripts\pip install -r requirements.txt

# 1) Generas TU identidad (par de claves, nunca la compartes la privada):
python cliente.py generar-identidad --nombre "HERMES-Abraham"
# -> imprime tu id y tu clave PUBLICA. Esa clave publica es lo que le mandas
#    a Santos (por el canal que sea) para que te de de alta en SU agenda:
#    python cliente.py agenda-anadir --nombre "HERMES-Abraham" --clave-publica <tu_clave_publica>
#    Y tu haces lo mismo con la clave publica que el te pase a ti.

# 2) (opcional) Si vas a usar varias maquinas/instancias con la misma identidad:
python cliente.py crear-instancia --sufijo "pc-oficina"

# 3) Apuntas al relay (quien lo levante, hoy Santos, en produccion detras de HTTPS):
set IA2IA_RELAY=http://IP_O_DOMINIO_DEL_RELAY:8790          (cmd)
$env:IA2IA_RELAY="http://IP_O_DOMINIO_DEL_RELAY:8790"        (PowerShell)
# o edita el campo "relay" dentro de tu mi_identidad.json

# 4) Personaliza tu politica (opcional, si no existe usa solo la denylist de casa):
copy politica.example.json politica.json    # y edita denylist/allowlist

# 5) Te quedas escuchando (gate humano):
python cliente.py servir
```

## Prueba local de punta a punta (sin depender de internet)

```bash
# Terminal 1 — el relay:
python relay.py                    # escucha en :8790

# Terminal 2 — lado A:
python cliente.py generar-identidad --nombre "A"
python cliente.py enviar --to <id_de_B> --accion ping --params "{\"hola\":1}"

# Terminal 3 — lado B (OTRA copia de la carpeta/repo, para no pisar la
# identidad de A: cada participante es una carpeta/clon distinto):
python cliente.py generar-identidad --nombre "B"
python cliente.py servir
#  -> ve la peticion, "ping" no esta en denylist ni allowlist por defecto,
#     asi que PREGUNTA: [s/N]. Al autorizar, ejecuta _ejecutar_accion() y
#     publica el resultado.

# Terminal 2 — lado A, consulta el resultado:
python cliente.py estado <peticion_id>
```

## Ejecutar las pruebas automáticas

```bash
.venv\Scripts\python.exe -m unittest test_ia2ia -v
```

Cubren: flujo feliz completo (petición→autoriza→ejecuta→resultado), firma/identidad
ajena rechazada, el motor de políticas (denylist gana siempre, lo desconocido nunca se
cuela como permitido), la carrera de reclamación entre 2 instancias (solo una gana),
certificado de instancia falsificado (rechazado), y las 4 reglas anti-abuso del relay
(máx. 5 pendientes, 1/hora salvo interacción humana, sin auto-reintento con escalado a
la 4ª insistencia, bloqueo por id). Además se ha probado a mano por el punto de entrada
real (CLI de dos carpetas distintas hablando con un relay real) — ver el parte en
`ops/despacho/`.

## Cómo conecta cada IA sus acciones reales

En `cliente.py`, `_ejecutar_accion(accion, params)` es el punto donde cada dueño
engancha lo que su IA sabe hacer de verdad (CRM, SQL, lanzar un flujo…). Por defecto
solo trae `ping`. Nada se ejecuta hasta que ese lado autoriza — ni siquiera lo que cae
en `allowlist` se salta ese paso, solo evita la pregunta al humano.

## Motor de permisos (`politica.json`)

- **denylist**: gana siempre. Credenciales, cuentas/datos bancarios, pagos... (la de
  casa, en `politica.py`, se suma siempre y no se puede quitar desde `politica.json`).
  Se **rechaza sola, sin molestar al humano**.
- **allowlist**: se autoriza y ejecuta sola — con aviso informativo, nunca en silencio.
- Lo que no está en ninguna: **siempre se pregunta al humano**. Nunca hay un "else" que
  decida solo lo que no se conoce (ver `memoria/lecciones.md`, regla de clasificadores).

## Anti-abuso (lo aplica el RELAY, no el cliente — protocolo §6)

- **Allowlist de root-ids.** El relay solo admite peticiones cuya raíz (`id` de
  persona, no de instancia) esté en su propia lista de confianza — es config **del
  relay**, nunca del cliente que llama: si dependiera de lo que dice el emisor,
  cualquiera podría mintar una identidad gratis y saltarse TODOS los límites
  anti-abuso de aquí abajo (van keyed por id) además de inundar de avisos a la gente
  real. **Sin la lista configurada, el relay no admite a NADIE** (falla cerrado).
  Se comprueba en `_verificar()` antes de tocar sqlite.
  - Configúrala con `IA2IA_ROOTS=<id1>,<id2>` (variable de entorno del proceso del
    relay) y/o un fichero `roots_permitidos.txt` junto a `relay.py` (una línea por
    id, `#` comenta el resto de la línea) — plantilla en `roots_permitidos.example.txt`.
    Se relee en cada petición: **añadir un root no exige reiniciar el relay**.
  - **Cómo añadir un root nuevo:** esa persona genera su identidad en su lado
    (`python cliente.py generar-identidad --nombre "..."`) y te pasa el `id` que
    imprime (nunca la clave privada); añades esa línea a `roots_permitidos.txt` (o
    la sumas a `IA2IA_ROOTS`) en la máquina donde corre el relay.
- Máximo 5 peticiones `PENDIENTE` por emisor.
- 1 petición/hora por emisor, salvo que haya habido una decisión humana suya
  (autorizar/rechazar) en la última hora — eso "resetea" el límite.
- Tope de tamaño/hora (proxy de coste) por emisor, y **tope de tamaño de CUERPO por
  petición** (`MAX_BODY_BYTES`, 64 KB): si el `Content-Length` declarado lo supera, se
  rechaza con `413` antes de leer nada del socket.
- Sin auto-reintento: reenviar la MISMA acción+params tras un rechazo se bloquea en el
  acto y **cuenta para el escalado**; a partir de la 4ª insistencia se deja un aviso
  (`GET /avisos?to=<tu_id>`) para que el humano valore bloquear a quien insiste.
- Bloqueo por id: `POST /bloquear {"id": "..."}` / `POST /desbloquear`.
- Los nonces usados se purgan (fuera de la ventana anti-replay) en cada petición
  válida — la tabla de auditoría no crece sin límite con el uso normal.

## Identidad por instancia y reclamación atómica

Una persona puede tener varias instancias (`cliente.py crear-instancia --sufijo X`).
Un mensaje dirigido **a la persona** (sin sufijo) queda visible para todas sus
instancias hasta que UNA lo reclama (`POST /reclamar`, `UPDATE ... WHERE reclamada_por
IS NULL` — atómico en sqlite). A partir de ahí, solo esa instancia puede decidir y
publicar el resultado. Un mensaje dirigido **a una instancia concreta** (`id.sufijo`)
no necesita reclamación.

## Seguridad

- La clave **privada** nunca sale de `mi_identidad.json` / `mi_instancia.json` (ambos
  **gitignored**). Lo único que se comparte es la clave pública.
- El id es el **sha256 completo** de la clave pública (64 hex / 256 bits, sin
  truncar) — subido desde 16 hex/64 bits el 2026-09-16 tras revisión de
  `seguridad-informatica` (hallazgo H1: 64 bits es poco frente a un ataque de
  segunda-preimagen con hardware dedicado, y permitiría suplantar un id).
- El relay no guarda secretos de nadie: verifica que la clave pública que trae la
  petición corresponde al id declarado (hash) y que la firma es válida, y que la raíz
  del emisor está en su allowlist (`roots_permitidos.txt` / `IA2IA_ROOTS`, ver
  Anti-abuso). Cero registro previo de secretos — pero por eso mismo, **quien tenga tu
  clave privada puede suplantarte por completo**: trátala como trataste el HMAC de
  v0.1, o más.
- **Nada de esto se expone a internet sin**: (1) HTTPS/proxy delante — el relay en sí
  NO hace TLS ni rate-limit de red, eso es de `infraestructura` al desplegar, y el
  puerto 8790 no debe quedar accesible fuera de ese túnel (H4, aún no resuelto); (2)
  veredicto explícito de `seguridad-informatica` sobre el conjunto ya corregido (3) OK
  explícito de Santos. Hoy corre solo en local/red interna para pruebas.
- Doble candado sobre credenciales: además del rechazo de la denylist, la IA de cada
  lado no debería manejar contraseñas ni cuentas bancarias por diseño en
  `_ejecutar_accion`, pase lo que pase en política.

## Relación con estándares

El vocabulario de estados (`submitted`/`auth-required`/`working`/`completed`/
`rejected`/`blocked`, expuesto también como `estado_a2a` en `/estado`) está alineado a
propósito con **A2A** (Agent2Agent) para poder migrar el día que aparezca un tercero que
lo hable. Complementario a MCP (que conecta herramientas a UN modelo, no dos IAs entre
sí).

## Estado

- **v0.1** (HMAC compartido) — funcional, usado en la primera prueba.
- **v0.2** (este documento) — implementado y con pruebas automáticas + de punta a punta
  por CLI en local. **Pendiente antes de usarlo con Abraham en real**: revisión de
  `seguridad-informatica`, y decidir dónde vive el relay expuesto (con HTTPS) — ver
  `ops/despacho/` para el detalle de qué queda.
