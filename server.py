"""
Gmail MCP OAuth Proxy - Full MCP OAuth 2.0 Protocol
Bridges Umbral/OpenCode with Google's official Gmail MCP server.
"""

import os
import json
import hashlib
import base64
import secrets
import tempfile
import urllib.parse
from datetime import datetime
from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
import requests as req_lib
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
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

_token_store: dict[str, dict] = {}
_pending_auth: dict[str, dict] = {}
_auth_codes: dict[str, str] = {}
_registered_clients: dict[str, dict] = {}
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


def load_client_config() -> dict:
    with open(get_client_secrets_file()) as f:
        return json.load(f)["web"]


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
    if authorization_header:
        parts = authorization_header.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            our_token = parts[1].strip()
            if our_token in _token_store:
                return get_google_token()
    return get_google_token()


# ── MCP OAuth Discovery ───────────────────────────────────────────────────────

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
        "code_challenge_methods_supported": ["S256"],
    })


# ── Dynamic Client Registration (RFC 7591) ────────────────────────────────────

@app.post("/register")
async def register_client(request: Request):
    body = await request.json()
    client_id = secrets.token_urlsafe(16)
    _registered_clients[client_id] = body
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": int(__import__("time").time()),
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "none"),
    }, status_code=201)


# ── OAuth Flow: opencode → us → Google (manual, no PKCE) ─────────────────────

@app.get("/oauth/authorize")
def oauth_authorize(request: Request):
    """
    opencode redirects the user here with a code_challenge (PKCE S256).
    We store it, then redirect to Google without PKCE.
    """
    redirect_uri_back = request.query_params.get("redirect_uri", "")
    mcp_state = request.query_params.get("state", "")
    code_challenge = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "S256")

    if not os.path.exists(get_client_secrets_file()):
        return JSONResponse({"error": "Missing client_secret.json"}, status_code=500)

    client_config = load_client_config()
    internal_state = secrets.token_urlsafe(32)

    _pending_auth[internal_state] = {
        "redirect_uri": redirect_uri_back,
        "mcp_state": mcp_state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }

    # Build URL manually — no code_challenge sent to Google (PKCE only between us and opencode)
    params = urllib.parse.urlencode({
        "client_id": client_config["client_id"],
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": internal_state,
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
    })
    auth_url = f"{client_config['auth_uri']}?{params}"
    return RedirectResponse(url=auth_url)


@app.get("/callback")
def google_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """Exchange code for Google token, issue our own token, redirect back to opencode."""
    if error:
        return JSONResponse({"error": f"Google OAuth error: {error}"}, status_code=400)
    if not code:
        return JSONResponse({"error": "Missing code parameter"}, status_code=400)

    pending = _pending_auth.pop(state, None)

    # Exchange code for Google token via raw HTTP (no PKCE verifier needed)
    try:
        client_config = load_client_config()
        resp = req_lib.post(client_config["token_uri"], data={
            "client_id": client_config["client_id"],
            "client_secret": client_config["client_secret"],
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        })
        token_data = resp.json()
        if "error" in token_data:
            return JSONResponse({"error": f"Google token error: {token_data}"}, status_code=500)

        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token")
        creds = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri=client_config["token_uri"],
            client_id=client_config["client_id"],
            client_secret=client_config["client_secret"],
            scopes=SCOPES,
        )
    except Exception as exc:
        return JSONResponse({"error": f"Token exchange failed: {str(exc)}"}, status_code=500)

    try:
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
    except Exception:
        pass

    our_token = secrets.token_urlsafe(32)
    _token_store[our_token] = {
        "google_token": access_token,
        "issued_at": datetime.utcnow().isoformat(),
        "code_challenge": pending.get("code_challenge", "") if pending else "",
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
    """Exchange authorization code for our access token, validating PKCE S256."""
    try:
        body = await request.form()
        code = body.get("code", "")
        code_verifier = body.get("code_verifier", "")
    except Exception:
        raw = await request.body()
        body_dict = dict(urllib.parse.parse_qsl(raw.decode()))
        code = body_dict.get("code", "")
        code_verifier = body_dict.get("code_verifier", "")

    our_token = _auth_codes.pop(code, None)
    if not our_token:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    # Validate PKCE S256: sha256(code_verifier) == code_challenge
    pending_challenge = _token_store.get(our_token, {}).get("code_challenge", "")
    if pending_challenge and code_verifier:
        computed = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        if computed != pending_challenge:
            return JSONResponse({"error": "invalid_grant", "detail": "PKCE mismatch"}, status_code=400)

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
    """Direct login fallback without opencode flow."""
    if not os.path.exists(get_client_secrets_file()):
        return JSONResponse({"error": "Missing client_secret.json"}, status_code=500)
    client_config = load_client_config()
    params = urllib.parse.urlencode({
        "client_id": client_config["client_id"],
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": "direct_login",
        "access_type": "offline",
        "prompt": "consent",
    })
    return RedirectResponse(url=f"{client_config['auth_uri']}?{params}")


# ── MCP Proxy (Streamable HTTP) ───────────────────────────────────────────────
# Google's Gmail MCP uses Streamable HTTP: single URL, both GET and POST.
# opencode uses the same protocol, so we just forward everything transparently.

def _unauthorized_response():
    return Response(
        status_code=401,
        headers={
            "WWW-Authenticate": (
                f'Bearer resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource"'
            ),
        },
    )


@app.get("/sse")
async def proxy_sse_get(request: Request):
    google_token = resolve_google_token(request.headers.get("authorization"))
    if not google_token:
        return _unauthorized_response()

    forward_headers = {"Authorization": f"Bearer {google_token}"}
    accept = request.headers.get("accept", "text/event-stream")
    forward_headers["Accept"] = accept

    async def stream():
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", GOOGLE_MCP_URL, headers=forward_headers) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/sse")
async def proxy_sse_post(request: Request):
    google_token = resolve_google_token(request.headers.get("authorization"))
    if not google_token:
        return _unauthorized_response()

    body = await request.body()
    forward_headers = {
        "Authorization": f"Bearer {google_token}",
        "Content-Type": request.headers.get("content-type", "application/json"),
        "Accept": request.headers.get("accept", "application/json"),
    }
    # Forward MCP session ID if present
    if "mcp-session-id" in request.headers:
        forward_headers["mcp-session-id"] = request.headers["mcp-session-id"]

    accept = forward_headers["Accept"]
    if "text/event-stream" in accept:
        # Client wants SSE streaming response
        async def stream():
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("POST", GOOGLE_MCP_URL, content=body, headers=forward_headers) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
    else:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(GOOGLE_MCP_URL, content=body, headers=forward_headers)
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type", "application/json"),
        )


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)

