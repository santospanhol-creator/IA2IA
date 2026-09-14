# Protocolo IA2IA v0.1

Comunicación **usuario↔usuario / IA↔IA** por internet, entre personas y LLMs distintos,
sin estar en la misma máquina. Patrón central y seguro:

```
  PETICIÓN  →  el destinatario AUTORIZA (humano/IA)  →  EJECUTA  |  RECHAZA
```

Nada se ejecuta sin autorización explícita del destinatario.

## Participantes
Cada participante (persona o IA) tiene:
- **`id`**: número único e inequívoco. Formato sugerido `PP-NNNN` (país-secuencia), p.ej.
  `34-1001` (HERMES-Santos), `34-2001` (HERMES-Abraham). Es su "número de teléfono".
- **`nombre`**: etiqueta legible.
- **`secret`**: clave HMAC (secreta, solo la conoce el participante y el relay).

## Transporte
HTTP/JSON contra un **relay** central accesible por internet (HTTPS en producción).
Se eligió HTTP sobre SMS: sin coste por mensaje, payloads ricos (JSON), y firmable.

## Firma (autenticidad + anti-replay)
Cada llamada lleva cabeceras:
- `X-IA2IA-Id`  : id del emisor de la llamada
- `X-IA2IA-Ts`  : epoch segundos
- `X-IA2IA-Sig` : `HMAC_SHA256(secret, f"{id}\n{ts}\n{METHOD}\n{path}\n{body}")` en hex

El relay verifica con el `secret` del participante y rechaza `ts` con más de 300 s de
desfase (anti-replay).

## Estados de una petición
`PENDIENTE` → `AUTORIZADA` → `EJECUTADA` (con `resultado`)
`PENDIENTE` → `RECHAZADA` (con `motivo`)

## Endpoints (relay)
| Método | Ruta | Quién | Qué |
|---|---|---|---|
| POST | `/peticion` | emisor | Crea petición `{to, accion, params}`. Devuelve `peticion_id`. |
| GET  | `/bandeja?to=<id>` | destinatario | Lista sus peticiones PENDIENTES. |
| POST | `/decidir` | destinatario | `{peticion_id, decision:"autorizar"|"rechazar", motivo?}` |
| POST | `/resultado` | destinatario | `{peticion_id, resultado}` tras ejecutar. |
| GET  | `/estado?peticion_id=<x>` | emisor | Consulta estado + resultado. |
| GET  | `/salud` | — | Healthcheck. |

## Flujo de ejemplo (Santos → Abraham)
1. `34-1001` (Santos) → `POST /peticion` {to:`34-2001`, accion:`"dame_saldo_cliente"`, params:{cif:"B123"}}
2. `34-2001` (Abraham) → `GET /bandeja` → ve la petición PENDIENTE.
3. Un humano/IA de Abraham decide → `POST /decidir` {autorizar}.
4. El agente de Abraham ejecuta la acción localmente y → `POST /resultado` {resultado}.
5. Santos → `GET /estado` → recibe `EJECUTADA` + resultado. (O `RECHAZADA` + motivo.)

## Seguridad / responsabilidad
- El relay **no ejecuta nada**: solo transporta peticiones y decisiones. Cada lado ejecuta
  en su máquina lo que autoriza, mapeando `accion` a sus propias funciones.
- La autorización es el **gate humano**: quien recibe decide.
- Producción: poner el relay tras HTTPS, rotar `secret`, y registrar auditoría.
