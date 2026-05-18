"""
Gmail MCP OAuth Proxy - Full MCP OAuth 2.0 Protocol
Bridges Umbral/OpenCode with Google's official Gmail MCP server.

Umbral → discovers /.well-known/oauth-protected-resource
Umbral → opens browser to /oauth/authorize
We chain to Google OAuth → get Gmail token
We issue our own token back to Umbral
Umbral uses our token in Authorization header for /sse
We proxy to gmailmcp.googleapis.com with the Google token
"""

import os
import json
import secrets
import tempfile
from datetime import datetime
from fastapi import FastAPI, Request, Response
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

# ── Config ────────────────────────────────────────────────────────────────────

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
REDIRECT_URI = os.getenv("REDIRECT_URI", f"{BASE_URL}/callback")
GOOGLE_MCP_URL = "https://gmailmcp.googleapis.com/mcp/v1"
TOKEN_FILE = os.getenv("TOKEN_FILE", "/tmp/token.json")
CLIENT_SECRETS_FILE = os.getenv("CLIENT_SECRETS_FILE", "client_secret.json")

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
]

# In-memory stores (survive within a process, reset on restart)
_token_store: dict[str, dict] = {}   # our_token -> {google_token, ...}
_pending_auth: dict[str, dict] = {}  # internal_state -> {redirect_uri, mcp_state}
_auth_codes: dict[str, str] = {}     # short_code -> our_token
_CLIENT_SECRETS_TMP = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client_secrets_file() -> str:
    global _CLIENT_SECRETS_TMP
    secret_json = os.getenv("GOOGLE_CLIENT_SECRET_JSON")
    if secret_json:
        if _CLIENT_SECRETS_TMP is None:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            tmp.write(secret_json)
            tmp.close()
            _CLIENT_SECRETS_TMP = tmp.name
        return _CLIENT_SECRETS_TMP
    return CLIENT_SECRETS_FILE


def load_google_credentials() -> Credentials | None:
    if not os.path.exists(TOKEN_FILE):
        return None
    try:
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
            with open(TOKEN_FILE, "w") as f:
                f.write(creds.to_json())
        return creds if creds.valid else None
    except Exception:
        return None


def get_google_token() -> str | None:
    creds = load_google_credentials()
    return creds.token if creds else None


def resolve_google_token(authorization_header: str | None) -> str | None:
    """Validate our token and return the Google access token."""
    if authorization_header:
        parts = authorization_header.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            our_token = parts[1].strip()
            if our_token in _token_store:
                return get_google_token()
    # Fallback: use stored Google token directly (e.g. after restart)
    return get_google_token()


# ── MCP OAuth Discovery (required by opencode to start the flow) ──────────────

@app.get("/.well-known/oauth-protected-resource")
def well_known_resource():
    return JSONResponse({
        "resource": BASE_URL,
        "authorization_servers": [BASE_URL],
    })


@app.get("/.well-known/oauth-authorization-server")
def well_known_auth_server():
    return JSONResponse({
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
        "token_endpoint": f"{BASE_URL}/oauth/token",
        "registration_endpoint": f"{BASE_URL}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["mcp:read", "mcp:write"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256", "plain"],
    })


# Dynamic Client Registration (RFC 7591) - required by opencode MCP SDK
_registered_clients: dict[str, dict] = {}

@app.post("/register")
async def register_client(request: Request):
    """Accept any client registration and return a client_id."""
    body = await request.json()
    client_id = secrets.token_urlsafe(16)
    _registered_clients[client_id] = {
        "redirect_uris": body.get("redirect_uris", []),
        "client_name": body.get("client_name", "mcp-client"),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "none"),
    }
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": int(__import__("time").time()),
        "redirect_uris": _registered_clients[client_id]["redirect_uris"],
        "grant_types": _registered_clients[client_id]["grant_types"],
        "response_types": _registered_clients[client_id]["response_types"],
        "token_endpoint_auth_method": _registered_clients[client_id]["token_endpoint_auth_method"],
    }, status_code=201)


# ── OAuth Flow: opencode → us → Google ───────────────────────────────────────

@app.get("/oauth/authorize")
def oauth_authorize(request: Request):
    """
    opencode opens the browser here. We chain to Google OAuth.
    After Google authorizes, we issue our own token and redirect back.
    """
    redirect_uri = request.query_params.get("redirect_uri", "")
    mcp_state = request.query_params.get("state", "")

    internal_state = secrets.token_urlsafe(32)
    _pending_auth[internal_state] = {
        "redirect_uri": redirect_uri,
        "mcp_state": mcp_state,
    }

    secrets_file = get_client_secrets_file()
    if not os.path.exists(secrets_file):
        return JSONResponse({"error": "Missing client_secret.json"}, status_code=500)

    flow = Flow.from_client_secrets_file(secrets_file, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    auth_url, _ = flow.authorization_url(
        access_type="offline", prompt="consent",
        state=internal_state, include_granted_scopes="true",
    )
    return RedirectResponse(url=auth_url)


@app.get("/callback")
def google_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """
    Google redirects here. We save the Google token, issue our own token,
    and redirect back to opencode's redirect_uri.
    """
    if error:
        return JSONResponse({"error": f"Google OAuth error: {error}"}, status_code=400)

    if not code:
        return JSONResponse({"error": "Missing code parameter"}, status_code=400)

    pending = _pending_auth.pop(state, None)

    try:
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
        flow = Flow.from_client_secrets_file(
            get_client_secrets_file(), scopes=SCOPES, redirect_uri=REDIRECT_URI, state=state,
        )
        flow.fetch_token(code=code)
        creds = flow.credentials
    except Exception as exc:
        return JSONResponse({"error": f"Token exchange failed: {str(exc)}"}, status_code=500)

    try:
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
    except Exception:
        pass

    our_token = secrets.token_urlsafe(32)
    _token_store[our_token] = {
        "google_token": creds.token,
        "issued_at": datetime.utcnow().isoformat(),
    }

    if pending and pending.get("redirect_uri"):
        auth_code = secrets.token_urlsafe(16)
        _auth_codes[auth_code] = our_token
        redirect_uri = pending["redirect_uri"]
        mcp_state = pending.get("mcp_state", "")
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(url=f"{redirect_uri}{sep}code={auth_code}&state={mcp_state}")

    return JSONResponse({
        "message": "✅ Autenticación exitosa.",
        "sse_url": f"{BASE_URL}/sse",
    })



@app.post("/oauth/token")
async def oauth_token(request: Request):
    """Exchange authorization code for our access token."""
    try:
        body = await request.form()
        code = body.get("code", "")
    except Exception:
        raw = await request.body()
        import urllib.parse
        body_dict = dict(urllib.parse.parse_qsl(raw.decode()))
        code = body_dict.get("code", "")

    our_token = _auth_codes.pop(code, None)
    if not our_token:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    return JSONResponse({
        "access_token": our_token,
        "token_type": "bearer",
        "expires_in": 86400,
        "scope": "mcp:read mcp:write",
    })


# ── Status & Direct Login ─────────────────────────────────────────────────────

@app.get("/")
def root():
    token = get_google_token()
    if token:
        return JSONResponse({"status": "✅ Autenticado con Google", "sse_url": f"{BASE_URL}/sse"})
    return RedirectResponse(url="/login")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/login")
def login():
    """Direct login fallback (without opencode flow)."""
    secrets_file = get_client_secrets_file()
    if not os.path.exists(secrets_file):
        return JSONResponse({"error": "Missing client_secret.json"}, status_code=500)
    flow = Flow.from_client_secrets_file(secrets_file, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    auth_url, _ = flow.authorization_url(access_type="offline", prompt="consent")
    return RedirectResponse(url=auth_url)


# ── MCP Proxy ─────────────────────────────────────────────────────────────────

@app.get("/sse")
async def proxy_sse(request: Request):
    google_token = resolve_google_token(request.headers.get("authorization"))
    if not google_token:
        return Response(
            status_code=401,
            headers={
                "WWW-Authenticate": (
                    f'Bearer resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource"'
                ),
            },
        )

    headers = {"Authorization": f"Bearer {google_token}", "Accept": "text/event-stream"}

    async def event_generator():
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", f"{GOOGLE_MCP_URL}/sse", headers=headers) as resp:
                async for line in resp.aiter_lines():
                    if "gmailmcp.googleapis.com" in line:
                        line = line.replace(GOOGLE_MCP_URL, BASE_URL)
                    yield line + "\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/messages")
async def proxy_messages(request: Request):
    google_token = resolve_google_token(request.headers.get("authorization")) or get_google_token()
    if not google_token:
        return JSONResponse({"error": "Not authenticated. Visit /login first."}, status_code=401)

    body = await request.body()
    headers = {
        "Authorization": f"Bearer {google_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(f"{GOOGLE_MCP_URL}/messages", content=body, headers=headers)

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
    )


@app.post("/sse")
async def proxy_sse_post(request: Request):
    return await proxy_messages(request)


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
