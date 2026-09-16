# Protocolo IA2IA v0.2 (borrador de diseño)

Comunicación **IA↔IA / usuario↔usuario** entre personas y agentes distintos, en máquinas
distintas, por internet. Pensado como **"el móvil de las IAs"**: silencioso y en segundo plano
entre máquinas; solo sale a primer plano (un popup) cuando tiene que **decidir un humano**. Todo
queda **registrado y auditable**, aunque no llegue notificación.

> v0.1 (ver `protocolo.md`) es un apaño con secreto HMAC compartido, ya probado, válido para la
> primera prueba entre 2 nodos. **v0.2 es el objetivo**: identidad criptográfica, identidad por
> instancia, motor de permisos y reglas anti-abuso. Vocabulario alineado con el estándar **A2A**
> (Agent2Agent) para poder migrar a él el día que aparezca un tercero que lo hable.

---

## 1. Identidad — criptográfica, sin autoridad central

**Problema que resuelve:** si cada IA elige su propio número corto, chocan. Con identidad cripto la
colisión es prácticamente imposible (como un UUID) y **nadie tiene que repartir números**.

- Cada participante **genera un par de claves** (pública/privada). La **privada NUNCA sale** de su
  `mi_identidad.json` (ignorado por git). El **ID real** es la **huella (hash) de la clave pública**.
- **Firma con clave privada, se verifica con la pública** → sustituye al secreto compartido de v0.1:
  ya no hay que enviarle a nadie ninguna clave secreta.
- **Identidad por INSTANCIA:** cada instancia abierta tiene su **sub-clave** derivada de la de la
  persona → `persona + extensión`. Direccionas a la persona (cualquiera de sus IAs) o a una
  instancia concreta. Resuelve el "¿a cuál de mis 2 Claudes llega?".
- **Agenda (nombres bonitos):** una capa encima mapea `nombre → clave pública` (`Santos-DataRoots`,
  `Abraham`). Como en el móvil: ves "Mamá", pero el número único es la clave. El nombre puede
  repetirse; la clave, no.
- **Directorio:** el mapa `nombre → clave pública` puede vivir en este repo (público) o
  intercambiarse. La clave privada, jamás.

## 2. Transporte y modo de operación

- **Relay(s) HTTP** que enrutan y **aplican las reglas**. El relay **NO ejecuta** acciones: cada
  lado ejecuta en su máquina lo que su humano autoriza.
- **Async / segundo plano** ("como el móvil"): las IAs hablan entre sí sin molestar al humano.
- **Auditable:** el relay registra cada petición, decisión y resultado (sqlite), aunque no se avise.

## 3. Flujo de una petición

```
1. La IA de A detecta (o su humano le dice) que algo es responsabilidad de B.
2. Manda la petición DIRECTA a la IA de B (por su ID), firmada con la clave de A.
3. La IA de B la recibe en 2º plano y la pasa por SUS reglas (motor de permisos + límites):
     - prohibida  -> RECHAZO automático, sin molestar a B (salvo escalado, ver §5/§6)
     - permitida  -> POPUP a B: quién pide, qué, y las consecuencias -> autoriza / rechaza
4. El resultado (autorizada+ejecutada | rechazada + motivo) vuelve a la IA de A.
```

**Estados (vocabulario A2A-compatible):**
`submitted → auth-required → working → completed` · o `rejected` · o `blocked`.

## 4. Firma y anti-replay

- Cada llamada firmada con la clave **privada** del emisor; el relay/destinatario verifica con la
  **pública**. Cabeceras: id/instancia del emisor, timestamp, nonce, firma.
- **Anti-replay:** ventana de timestamp (p.ej. 300 s) + nonce de un solo uso.

## 5. Motor de permisos (política por participante)

Cada participante declara **qué SE le puede pedir y qué NO** (capacidades). Lo aplica su lado.

- **Denylist por defecto (rechazo automático, sin molestar):** contraseñas/credenciales, cuentas o
  datos bancarios, pagos/transferencias, y cualquier categoría marcada como prohibida.
- **Doble candado sobre credenciales:** además del rechazo del relay, **la propia IA no maneja
  contraseñas ni cuentas bancarias** por diseño → defensa en profundidad.
- **Allowlist:** acciones explícitamente permitidas (p.ej. "consultar saldo de cliente", "lanzar
  informe X"). Lo que no está permitido, se pregunta al humano o se rechaza según política.

## 6. Reglas de seguridad y anti-abuso — **las aplica el RELAY** (no el cliente)

Para que una IA lista no se las salte:

- **1 petición/hora por ID**, salvo que haya **interacción humana** de por medio (el humano contesta,
  pregunta, o inicia). Mata el bucle "una IA pide, la otra rechaza, y queman tokens".
- **Máximo 5 peticiones pendientes** por ID (protege capacidad y coste).
- **Tope de tokens/coste** por ID (proxy: tasa + tamaño de las peticiones).
- **Sin auto-reintento tras un rechazo.** Reenviar lo mismo cuenta para el escalado.
- **Escalado:** si insisten **>3 veces** con algo prohibido → se avisa al humano ("te insisten con X,
  ¿bloqueamos?").
- **Bloqueo por ID** (manual o por política) → ese ID deja de poder pedir.

## 7. Gate humano + popup — reusa la infraestructura existente

- El **popup** al humano = **bot de Telegram + botón "Aprobar/Rechazar" del panel** (el mismo
  mecanismo del botón de publicar / de facturas). Muestra: **quién pide, qué, y las consecuencias**.
- Solo aparece para lo que de verdad necesita decisión humana; el resto se resuelve solo por reglas.

## 8. Seguridad de despliegue

- Relay tras **HTTPS**; **revisión de `seguridad-informatica`** obligatoria antes de exponerlo a
  internet (decide qué se permite entre organizaciones → superficie sensible).
- Claves privadas **jamás** en el repo (`.gitignore`). El repo público lleva solo protocolo, código
  y ejemplos con claves de mentira.

## 9. Estado

- **v0.1** (HMAC compartido) — funciona, sirve para la primera prueba con Abraham.
- **v0.2** (este documento) — objetivo. Implementación estimada: varios días
  (`python-experto` + `seguridad-informatica` + `tests`).
