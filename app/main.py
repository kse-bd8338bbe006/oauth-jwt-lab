"""
oauth-jwt-lab - deliberately vulnerable API for the API Security course, Lecture 11.

It backs the practical session on OAuth attacks, JWT abuse, and authorization testing.
One small "Docs" API with three roles worth of behavior, plus a JWT verifier that is
deliberately broken so students can forge tokens - and an OAuth callback page for the
Keycloak exercises.

A single switch decides the JWT verifier's behavior:

    SECURE_MODE=false  (default)  -> the broken verifier, so the three JWT attacks work
    SECURE_MODE=true              -> the fixed verifier, so they all fail

JWT abuse the broken verifier allows (all from the token's own `alg` header):
  * alg:none               - an unsigned token is accepted
  * weak HMAC secret       - HS256 signed with a short secret ("secret") is accepted;
                             crack it from a real /login token with jwt_tool / hashcat
  * RS256 -> HS256 confusion- HS256 signed with the server's RSA *public key* is accepted

Authorization (the "authorization matrix" exercise):
  * GET  /api/docs/{id}    - object-level: you may read only a doc you own (BOLA target)
  * GET  /api/admin/users  - function-level: admin only (BFLA target)
The caller's identity and role come straight from the (forgeable) JWT, so the two topics
chain: forge role=admin, then reach the admin route.

OAuth (items 1-3 use the lab Keycloak; this only hosts the redirect target):
  * GET  /callback         - shows the ?code / #fragment the AS sent back, so the flows
                             work with this deployed URL as the client's redirect_uri.

It is deliberately dependency-light and readable - teaching material, not a framework.
"""
import base64
import hashlib
import hmac
import json
import os
import time

import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

SECURE_MODE = os.environ.get("SECURE_MODE", "false").lower() in ("1", "true", "yes")

# --- keys / secrets (lab only; regenerated each start) -----------------------
# The weak HMAC secret a student is meant to crack. Short + in a wordlist on purpose.
WEAK_HS_SECRET = os.environ.get("WEAK_HS_SECRET", "secret")
# A strong secret used only in SECURE_MODE.
STRONG_HS_SECRET = os.environ.get("STRONG_HS_SECRET", base64.b64encode(os.urandom(48)).decode())

# An RSA keypair. The PUBLIC half is served at /jwks and /public.pem - it is meant to be
# public, which is exactly what makes the RS256->HS256 confusion attack possible.
_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PRIV_PEM = _rsa.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()).decode()
RSA_PUB_PEM = _rsa.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

ISSUER = "oauth-jwt-lab"

app = FastAPI(title="oauth-jwt-lab", version="1.0.0")

# --- demo data ---------------------------------------------------------------
# Passwords == usernames. Only alice/bob are real users; role is "user" for both.
USERS = {"alice": "alice", "bob": "bob"}
# Docs: each owned by one user. BOLA target - the owner check is what the API must do.
DOCS = {
    "d-1": {"id": "d-1", "owner": "alice", "title": "Alice roadmap", "body": "secret A"},
    "d-2": {"id": "d-2", "owner": "alice", "title": "Alice salary", "body": "secret A2"},
    "d-3": {"id": "d-3", "owner": "bob", "title": "Bob notes", "body": "secret B"},
}


# --- helpers -----------------------------------------------------------------
def b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def issue_token(sub: str, role: str) -> str:
    """A normal login token. HS256 with the weak secret in vuln mode (so it is
    crackable), the strong secret in secure mode."""
    secret = STRONG_HS_SECRET if SECURE_MODE else WEAK_HS_SECRET
    return jwt.encode(
        {"iss": ISSUER, "sub": sub, "role": role, "iat": int(time.time()),
         "exp": int(time.time()) + 3600},
        secret, algorithm="HS256")


class AuthError(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def verify_vulnerable(token: str) -> dict:
    """DELIBERATELY BROKEN: the token's own `alg` header decides how it is checked.

    This one function enables all three JWT attacks:
      - alg:none            -> signature skipped
      - HS256 + weak secret -> forged with a guessable/cracked key
      - HS256 + public key  -> RS256->HS256 confusion
    """
    header = jwt.get_unverified_header(token)
    alg = (header.get("alg") or "").lower()

    if alg == "none":  # BUG 1: accept unsigned tokens
        payload_b64 = token.split(".")[1]
        return json.loads(b64url_decode(payload_b64))

    if alg == "hs256":
        # BUG 2 + 3: verify HMAC by hand so we accept a token signed with EITHER the weak
        # secret (weak-HMAC) or the RSA public key (RS256->HS256 confusion). A hand-rolled
        # verifier like this is exactly what libraries such as PyJWT refuse to do for you -
        # PyJWT blocks a PEM public key as an HMAC key precisely to stop this attack.
        h_b64, p_b64, sig_b64 = token.split(".")
        signing_input = f"{h_b64}.{p_b64}".encode()
        got = b64url_decode(sig_b64)
        for key in (WEAK_HS_SECRET.encode(), RSA_PUB_PEM.encode()):
            expected = hmac.new(key, signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(expected, got):
                return json.loads(b64url_decode(p_b64))
        raise AuthError("hs256 signature invalid")

    if alg in ("rs256", "rs384", "rs512"):
        try:
            return jwt.decode(token, RSA_PUB_PEM, algorithms=["RS256"], options={"verify_aud": False})
        except Exception as e:
            raise AuthError(f"rs256 invalid: {e}")

    raise AuthError(f"unsupported alg {alg}")


def verify_secure(token: str) -> dict:
    """FIXED: the server pins the algorithm and the key; the header cannot choose.

    HS256 with the strong secret only. `none` and RS256/confusion are rejected because
    they are not in the algorithm allowlist and the key is not the token's to pick.
    """
    try:
        return jwt.decode(token, STRONG_HS_SECRET, algorithms=["HS256"],
                          issuer=ISSUER, options={"verify_aud": False})
    except Exception as e:
        raise AuthError(f"invalid token: {type(e).__name__}")


def current_user(authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthError("no bearer token")
    token = authorization[len("Bearer "):].strip()
    claims = verify_secure(token) if SECURE_MODE else verify_vulnerable(token)
    if not claims.get("sub"):
        raise AuthError("token has no subject")
    return claims


def _deny(err: AuthError):
    return JSONResponse(status_code=401, content={"error": "unauthorized", "reason": err.reason})


# --- key material endpoints (public on purpose) ------------------------------
@app.get("/health")
def health():
    return {"status": "UP", "service": "oauth-jwt-lab", "secure_mode": SECURE_MODE}


@app.get("/public.pem", response_class=HTMLResponse)
def public_pem():
    # The RSA public key in PEM - the exact bytes to use as the HMAC secret for the
    # RS256->HS256 confusion attack.
    return HTMLResponse(RSA_PUB_PEM, media_type="text/plain")


@app.get("/jwks")
def jwks():
    numbers = _rsa.public_key().public_numbers()

    def b64u(i: int) -> str:
        b = i.to_bytes((i.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "lab-rsa",
                      "n": b64u(numbers.n), "e": b64u(numbers.e)}]}


# --- auth (item 4: JWT abuse) ------------------------------------------------
@app.post("/login")
async def login(request: Request):
    body = await request.json()
    u, p = body.get("username"), body.get("password")
    if USERS.get(u) != p:
        raise HTTPException(status_code=401, detail="bad credentials")
    return {"access_token": issue_token(u, "user"), "token_type": "Bearer"}


@app.get("/api/me")
def me(authorization: str | None = Header(default=None)):
    try:
        claims = current_user(authorization)
    except AuthError as e:
        return _deny(e)
    return {"sub": claims.get("sub"), "role": claims.get("role")}


# --- authorization (item 5: the authorization matrix) ------------------------
@app.get("/api/docs/{doc_id}")
def get_doc(doc_id: str, authorization: str | None = Header(default=None)):
    """Object-level authorization (BOLA). The caller may read only a doc they own."""
    try:
        claims = current_user(authorization)
    except AuthError as e:
        return _deny(e)
    doc = DOCS.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="not found")
    # VULN (BOLA): the owner check is only enforced in secure mode. In vulnerable mode any
    # authenticated caller reads any doc by its id - the classic object-level authz gap.
    if SECURE_MODE and doc["owner"] != claims.get("sub"):
        raise HTTPException(status_code=403, detail="not your document")
    return doc


@app.get("/api/admin/users")
def admin_users(authorization: str | None = Header(default=None)):
    """Function-level authorization (BFLA). Admin role only."""
    try:
        claims = current_user(authorization)
    except AuthError as e:
        return _deny(e)
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return {"users": list(USERS.keys()), "note": "you reached an admin-only function"}


# --- OAuth (items 1-3: redirect target for the Keycloak flows) ---------------
@app.get("/callback", response_class=HTMLResponse)
def callback():
    # Displays the query (?code=/?state=) and the fragment (#access_token=) the AS returns,
    # so the browser OAuth exercises have a working redirect_uri.
    return HTMLResponse(
        """<!doctype html><meta charset=utf-8><title>OAuth callback</title>
        <body style="font-family:monospace;padding:1rem">
        <h3>OAuth callback captured</h3>
        <p><b>Query</b> (code flow):</p><pre id=q></pre>
        <p><b>Fragment</b> (implicit flow):</p><pre id=f></pre>
        <script>
        document.getElementById('q').textContent = location.search || '(none)';
        document.getElementById('f').textContent = location.hash || '(none)';
        </script></body>""")
