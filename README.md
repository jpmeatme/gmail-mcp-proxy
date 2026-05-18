# Gmail MCP OAuth Proxy

Proxy OAuth que conecta Umbral/OpenCode con el servidor oficial de Gmail MCP de Google.

## Cómo funciona

```
Umbral ──SSE──► Este servidor ──HTTPS+Bearer──► gmailmcp.googleapis.com
```

Este servidor:
1. Maneja el flujo OAuth con Google (`/login` → `/callback`) y guarda el token.
2. Cuando Umbral se conecta a `/sse`, abre una conexión SSE hacia Google inyectando el `Authorization: Bearer <token>`.
3. Reenvía todos los mensajes JSON-RPC de Umbral hacia Google y devuelve la respuesta.

## Variables de entorno (Render)

| Variable | Descripción |
|---|---|
| `BASE_URL` | URL pública del servidor en Render (ej: `https://gmail-mcp-proxy.onrender.com`) |
| `REDIRECT_URI` | URL de callback OAuth (`${BASE_URL}/callback`) |
| `SESSION_SECRET` | Clave secreta para las sesiones (Render la genera automáticamente) |
| `TOKEN_FILE` | Ruta donde guardar el token (por defecto `/tmp/token.json`) |
| `CLIENT_SECRETS_FILE` | Ruta al JSON de credenciales de Google Cloud |

## ⚠️ Nota sobre el `client_secret.json` en Render

El archivo `client_secret.json` NO se puede guardar en el repositorio de GitHub (es secreto).
Para subirlo a Render, tienes dos opciones:

**Opción A (Recomendada):** Convierte el contenido del JSON en una variable de entorno:
1. Copia todo el contenido de tu `client_secret.json`.
2. En Render → Environment → Add a new variable: `GOOGLE_CLIENT_SECRET_JSON` = **(el contenido)**
3. En `server.py`, reemplaza la lectura del archivo por `json.loads(os.getenv("GOOGLE_CLIENT_SECRET_JSON"))`.

**Opción B:** Usar un Render Disk (almacenamiento persistente).

## Deploy

1. Sube esta carpeta a un repositorio de GitHub.
2. En render.com → New Web Service → conecta tu repo.
3. Render detecta `render.yaml` automáticamente.
4. Una vez desplegado, copia la URL de Render.
5. En Google Cloud Console → Credenciales → Agrega la URL de callback: `https://tu-url.onrender.com/callback`
6. Visita `https://tu-url.onrender.com/login` para autorizar con Gmail.

## Configurar en Umbral (`opencode.jsonc`)

```jsonc
{
  "mcp": {
    "gmail": {
      "type": "remote",
      "url": "https://tu-url.onrender.com/sse"
    }
  }
}
```
