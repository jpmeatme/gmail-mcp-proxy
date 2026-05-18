"""
Gmail MCP OAuth Proxy
Bridges Umbral (OpenCode) with Google's official Gmail MCP server.

Flow:
  Umbral <---SSE---> This Proxy <---HTTPS+Bearer---> gmailmcp.googleapis.com/mcp/v1
"""

import os
import json
import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import uvicorn

app = FastAPI(title="Gmail MCP OAuth Proxy")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "change-me-in-production"),
)

# ─── Configuración ───────────────────────────────────────────────────────────
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
REDIRECT_URI = os.getenv("REDIRECT_URI", f"{BASE_URL}/callback")

GOOGLE_MCP_URL = "https://gmailmcp.googleapis.com/mcp/v1"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
]

TOKEN_FILE = os.getenv("TOKEN_FILE", "token.json")
CLIENT_SECRETS_FILE = os.getenv("CLIENT_SECRETS_FILE", "client_secret.json")


# ─── Gestión de Tokens ───────────────────────────────────────────────────────

def load_credentials() -> Credentials | None:
    """Load and auto-refresh credentials from TOKEN_FILE."""
    if not os.path.exists(TOKEN_FILE):
        return None
    try:
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
            _save_credentials(creds)
        return creds if creds.valid else None
    except Exception:
        return None


def _save_credentials(creds: Credentials):
    with open(TOKEN_FILE, "w") as f:
        f.write(creds.to_json())


def get_access_token() -> str | None:
    creds = load_credentials()
    return creds.token if creds else None


# ─── Rutas de Estado ─────────────────────────────────────────────────────────

@app.get("/")
def root():
    token = get_access_token()
    if token:
        return {
            "status": "✅ Autenticado con Google",
            "proxy_sse_url": f"{BASE_URL}/sse",
            "instrucciones": "Apunta tu MCP en Umbral/opencode.jsonc a la URL de arriba.",
        }
    return RedirectResponse(url="/login")


@app.get("/health")
def health():
    return {"ok": True}


# ─── Flujo OAuth ─────────────────────────────────────────────────────────────

@app.get("/login")
def login(request: Request):
    if not os.path.exists(CLIENT_SECRETS_FILE):
        return JSONResponse(
            {"error": f"Falta {CLIENT_SECRETS_FILE}. Descárgalo de Google Cloud Console."},
            status_code=500,
        )
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(
        access_type="offline", prompt="consent", include_granted_scopes="true"
    )
    request.session["oauth_state"] = state
    return RedirectResponse(url=auth_url)


@app.get("/callback")
def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        return JSONResponse({"error": f"OAuth error: {error}"}, status_code=400)
    if state != request.session.get("oauth_state"):
        return JSONResponse({"error": "OAuth state mismatch."}, status_code=400)

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=state,
    )
    flow.fetch_token(authorization_response=str(request.url))
    _save_credentials(flow.credentials)
    return JSONResponse({
        "message": "✅ Autenticación exitosa.",
        "next": f"Ya puedes usar el MCP de Gmail. URL SSE: {BASE_URL}/sse",
    })


# ─── Proxy MCP ───────────────────────────────────────────────────────────────

def _auth_headers() -> dict:
    token = get_access_token()
    if not token:
        raise PermissionError("No hay token de Google. Visita /login primero.")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "text/event-stream",
    }


@app.get("/sse")
async def proxy_sse(request: Request):
    """
    Opens a real SSE connection to Google's Gmail MCP server, injects the
    Authorization header, and streams events back to the Umbral client.
    Any endpoint URL in the SSE stream that points to Google is rewritten to
    point to our proxy so that Umbral can POST back through us.
    """
    try:
        headers = _auth_headers()
    except PermissionError as exc:
        return JSONResponse({"error": str(exc)}, status_code=401)

    async def event_generator():
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", f"{GOOGLE_MCP_URL}/sse", headers=headers) as response:
                async for line in response.aiter_lines():
                    # Rewrite any Google message endpoint → our /messages proxy
                    if "gmailmcp.googleapis.com" in line:
                        line = line.replace(GOOGLE_MCP_URL, BASE_URL)
                    yield line + "\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/messages")
async def proxy_messages(request: Request):
    """
    Receives JSON-RPC messages from Umbral and forwards them to Google's
    Gmail MCP server with the Authorization header injected.
    """
    try:
        headers = _auth_headers()
    except PermissionError as exc:
        return JSONResponse({"error": str(exc)}, status_code=401)

    body = await request.body()
    headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{GOOGLE_MCP_URL}/messages",
            content=body,
            headers=headers,
        )
    return Response(
        content=response.content,
        status_code=response.status_code,
        media_type=response.headers.get("content-type", "application/json"),
    )


# Allow Umbral to also POST to /sse (some MCP clients use this route)
@app.post("/sse")
async def proxy_sse_post(request: Request):
    return await proxy_messages(request)


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
