# yummy-gateway

Pasarela (gateway) en **Go** que unifica el acceso a la **API de Yummy** para todos
nuestros proyectos (CRM, ecommerce, etc.). En lugar de mantener 3 gestores
distintos de Yummy, cada sistema habla un API simple y propio contra este
gateway, con **su usuario/clave y su URL de webhooks**.

```
                                  ┌──────────────────────────────┐
  CRM ──────── X-Gateway-Key ───▶ │                              │ ── x-api-key ──▶  Yummy API
  Ecommerce ── X-Gateway-Key ───▶ │       yummy-gateway          │
  ERP ──────── X-Gateway-Key ───▶ │  (Go + SQLite/WAL + Docker)  │ ◀── webhooks ───  Yummy
                                  │                              │
  CRM ◀─────── firmado HMAC ───── │   reintentos + cola de eventos│
  Ecommerce ◀─ firmado HMAC ───── │                              │
                                  └──────────────────────────────┘
```

**Qué resuelve**

| Problema | Solución |
|---|---|
| 3 proyectos con su propio gestor de Yummy | Una sola pasarela multi-tenant |
| La API key de Yummy vive en 3 codebases | Se guarda una vez, cifrada en el gateway y se inyecta por request |
| Cada proyecto recibe los mismos webhooks | El gateway verifica la firma, persiste el evento y lo **reenvía a la URL de cada tenant**, firmado y con reintentos |
| Diferentes privilegios por sistema | Cada clave del gateway tiene sus permisos (`stock:read`, `chat:write`, …) |
| Pierdes webhooks si un sistema está caído | Cola persistente: el evento se reintenta con backoff hasta 24 h y puede reintentarse a mano |

---

## Puesta en marcha

### Docker (recomendado)

```bash
cp .env.example .env
# Edita .env -> GATEWAY_ADMIN_TOKEN (openssl rand -hex 32)
#               GATEWAY_PUBLIC_BASE_URL (https://gw.tudominio.com)

docker compose up -d --build
curl http://localhost:8080/healthz
```

### Local (desarrollo)

```bash
export GATEWAY_ADMIN_TOKEN=dev-token
export GATEWAY_PUBLIC_BASE_URL=http://localhost:8080
go run ./cmd/gateway
```

---

## Conceptos

- **Tenant** — un proyecto nuestro (CRM, ecommerce…). Tiene: la API key de
  Yummy + su base URL, la URL a la que se le reenvían los webhooks, un secreto
  con el que el gateway firma esas entregas, y límites de rate limit.
- **Gateway key** (`gw_live_…`) — la clave que usa el proyecto para llamar al
  gateway. Se guarda hasheada (SHA-256) y solo se muestra **una vez** al
  crearse. Cada clave tiene su lista de permisos.
- **Webhook URL del tenant** — `GATEWAY_PUBLIC_BASE_URL/webhooks/y/{token}`.
  Es lo que se configura como `webhookUrl` de Yummy.

---

## API para los proyectos (`X-Gateway-Key`)

| Método y ruta | Permiso requerido | Equivalente en Yummy |
|---|---|---|
| `POST /v1/stock/sync` | `stock:write` | `POST /seller-api/v1/stock/sync` |
| `GET  /v1/stock` | `stock:read` | `GET /seller-api/v1/stock` |
| `PATCH /v1/sku` | `price:write` | `PATCH /seller-api/v1/sku` |
| `GET  /v1/orders` | `orders:read` | `GET /seller-api/v1/orders` |
| `GET  /v1/chat/messages` | `chat:read` | `GET /seller-api/v1/chat/messages` |
| `GET  /v1/chat/{chatId}/messages` | `chat:read` | `GET /seller-api/v1/chat/{chatId}/messages` |
| `POST /v1/chat/{chatId}/messages` | `chat:write` | `POST /seller-api/v1/chat/{chatId}/messages` |
| `*    /v1/yummy/{ruta}` | la que infiera la ruta | pasarela genérica a `/seller-api/v1/{ruta}` |

```bash
# Leer stock
curl -H "X-Gateway-Key: gw_live_..." \
  "http://localhost:8080/v1/stock?sku=CAMISA-AZUL-M&limit=10"

# Sincronizar stock
curl -X POST -H "X-Gateway-Key: gw_live_..." -H "Content-Type: application/json" \
  -d '{"items":[{"sku":"CAMISA-AZUL-M","branchExternalId":"SUC-001","stock":25,"operation":"set"}]}' \
  http://localhost:8080/v1/stock/sync

# Pasarela genérica (cualquier otro endpoint de Yummy)
curl -H "X-Gateway-Key: gw_live_..." \
  "http://localhost:8080/v1/yummy/orders?startDate=2026-07-01&endDate=2026-07-08"
```

También se acepta `Authorization: Bearer gw_live_...`.

**Respuestas de error** (siempre JSON):

```json
{"error": {"code": "MISSING_PERMISSION", "message": "this key does not have the permission price:write"}}
```

| Código HTTP | `error.code` | Significado |
|---|---|---|
| 401 | `MISSING_API_KEY` / `INVALID_API_KEY` | Falta o no existe la clave |
| 403 | `MISSING_PERMISSION` | La clave no tiene ese permiso |
| 429 | `RATE_LIMITED` | Rate limit del tenant (`Retry-After`) |
| 502 | `UPSTREAM_ERROR` | Yummy no respondió |
| 503 | `NO_UPSTREAM` / `NO_CREDENTIAL` | El tenant no tiene base URL o API key configuradas |

---

## API admin (`X-Admin-Token`)

Desactivada si `GATEWAY_ADMIN_TOKEN` está vacío.

```bash
GW=http://localhost:8080
AUTH="X-Admin-Token: $GATEWAY_ADMIN_TOKEN"

# 1) Dar de alta un tenant (proyecto)
curl -X POST -H "$AUTH" -H "Content-Type: application/json" -d '{
  "name": "CRM Principal",
  "slug": "crm",
  "callback_url": "https://crm.example.com/hooks/yummy",
  "yummy_base_url": "https://api.yummy...",
  "yummy_api_key": "mk_tst_...",
  "webhook_secret": "secreto-que-yummy-firma"
}' $GW/admin/tenants
# => { "id":"tnt_...", "webhook_url":"https://gw.../webhooks/y/...", "callback_secret":"..." }

# 2) Emitir la clave del proyecto (se muestra UNA sola vez)
curl -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"label":"crm-prod","permissions":["stock:read","stock:write","orders:read"]}' \
  $GW/admin/tenants/tnt_.../keys

# 3) Operación
curl -H "$AUTH" $GW/admin/tenants
curl -H "$AUTH" $GW/admin/tenants/tnt_...
curl -X PATCH -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"yummy_api_key":"mk_prd_..."}' $GW/admin/tenants/tnt_...
curl -X DELETE -H "$AUTH" $GW/admin/keys/key_...

# 4) Eventos de webhook (auditoría y reintentos)
curl -H "$AUTH" "$GW/admin/events?tenant_id=tnt_...&status=failed"
curl -H "$AUTH" $GW/admin/events/evt_...
curl -X POST -H "$AUTH" $GW/admin/events/evt_.../retry
```

**Permisos disponibles:** `stock:read`, `stock:write`, `price:write`,
`orders:read`, `chat:read`, `chat:write` y `*` (todo).

---

## Webhooks

### Entrada (desde Yummy hacia el gateway)

Configura en Yummy la URL `webhook_url` que devuelve el alta del tenant.
La firma se verifica con `webhook_secret` + `webhook_signature_header`
(por defecto `x-yummy-signature`) y `webhook_signature_format`:

| Formato | Valor del header |
|---|---|
| `hex` (defecto) | HMAC-SHA256 hex del body |
| `sha256` | `sha256=<hex>` |
| `t` | `t=<unix>,v1=<hex>` (HMAC sobre `<t>.<body>`) |
| `off` | sin verificación |

> ⚠️ La sección de webhooks del `.txt` de la API **no venía en la exportación**
> (solo aparece en el índice: payload, headers, verificación HMAC, códigos de
> error y límites). Estos formatos son configurables por tenant para que, con
> la doc completa, solo haya que ajustar dos campos por tenant
> (`webhook_signature_header` / `webhook_signature_format`) sin tocar código.

### Salida (del gateway hacia cada proyecto)

El evento se recibe, se verifica, **se persiste** y se reenvía en background a
`callback_url`:

```
POST {callback_url}
Content-Type: application/json
X-Gateway-Event-Id: evt_...
X-Gateway-Event-Type: order.items.sold
X-Gateway-Delivery-Id: evt_...
X-Gateway-Attempt: 1
X-Gateway-Timestamp: 1712345678
X-Gateway-Signature: t=1712345678,v1=<hex>
```

La firma se calcula como `HMAC-SHA256(callback_secret, "<timestamp>.<body>")`.
Verificación en Node:

```js
const crypto = require("crypto");

function verify(req, rawBody, secret) {
  const header = req.headers["x-gateway-signature"] || "";
  const [t, v1] = header.split(",").map(s => s.trim().slice(2));
  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${t}.${rawBody}`)
    .digest("hex");
  return crypto.timingSafeEqual(Buffer.from(v1), Buffer.from(expected));
}
```

Reintentos: `5s, 30s, 2m, 10m, 30m, 2h, 6h, 12h` (8 intentos) y después
queda `failed`; se puede reintentar con el endpoint admin. Ante una caída del
gateway, los eventos en vuelo vuelven a `pending` al arrancar.

**Idempotencia:** `X-Gateway-Event-Id` es estable entre intentos — usa ese
valor para deduplicar en el sistema receptor.

---

## Configuración

Ver [.env.example](.env.example). Resumen:

| Variable | Defecto | Descripción |
|---|---|---|
| `GATEWAY_LISTEN` | `:8080` | Dirección de escucha |
| `GATEWAY_DB_PATH` | `./data/gateway.db` | Archivo SQLite (`:memory:` para tests) |
| `GATEWAY_ADMIN_TOKEN` | *(vacío = admin off)* | Token de `/admin` |
| `GATEWAY_PUBLIC_BASE_URL` | `http://localhost:8080` | Base de las webhook URLs |
| `GATEWAY_UPSTREAM_TIMEOUT` | `30s` | Timeout hacia Yummy |
| `GATEWAY_DELIVER_TIMEOUT` | `10s` | Timeout de cada reenvío |
| `GATEWAY_WORKER_INTERVAL` | `1s` | Frecuencia del worker |
| `GATEWAY_AUTH_CACHE_TTL` | `15s` | TTL de la caché de claves en RAM |
| `GATEWAY_DEFAULT_RPS` / `_BURST` | `60` / `120` | Rate limit por tenant |
| `GATEWAY_LOG_LEVEL` / `_JSON` | `info` / `false` | Logging |

---

## Base de datos: por qué SQLite (y cómo pasar a MySQL)

El camino caliente —autenticar cada request— **no toca la base de datos**: las
claves se resuelven desde una caché en memoria (TTL configurable, invalidada
al instante ante cualquier cambio admin). La base se usa para tenants, claves
y la cola de eventos.

SQLite en modo **WAL** con un único escritor por lote da más rendimiento del
que necesita un puñado de proyectos, sin servidor de base de datos y con
backup por copia de archivo. El código está aislado detrás de la interfaz
`store.Store` ([internal/store/store.go](internal/store/store.go)):

```go
type Store interface {
    CreateTenant(ctx, *Tenant) error
    ResolveKey(ctx, keyHash string) (*Tenant, *ProxyKey, error)
    ClaimDueEvents(ctx, now time.Time, limit int) ([]*WebhookEvent, error)
    // ...
}
```

**Migrar a MySQL** = implementar `MySQLStore` y elegirlo en `main`; los
handlers no cambian. Conviene hacerlo cuando:

- se necesiten **varias instancias** del gateway detrás de un balanceador, o
- otros sistemas deban consultar los mismos datos con SQL propio.

---

## Desarrollo

```bash
go vet ./...
go test ./...
go build ./cmd/gateway
```

Estructura:

```
cmd/gateway/          arranque, señales, graceful shutdown
internal/config/      configuración por variables de entorno
internal/store/       interfaz Store + implementación SQLite/WAL
internal/gateway/     auth, proxy, webhooks, admin, rate limit, logging
```

## Pendiente / siguiente pasos

- [ ] Confirmar con Yummy los headers y formato exactos de firma de sus
      webhooks (falta la sección en la documentación exportada).
- [ ] TLS obligatorio + allowlist de IPs de origen para el receptor de webhooks.
- [ ] `MySQLStore` cuando hagan falta varias instancias.
