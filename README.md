# oauth-jwt-lab

A **deliberately vulnerable API** for the API Security course, Lecture 11. It backs the
practical session on **JWT abuse** and **authorization testing**, and hosts the OAuth
**redirect target** for the Keycloak flow exercises.

Deployed in the lab at **https://oauth-jwt-lab.192.168.50.10.nip.io** (GitOps via
`kse-labs-deployment` -> `applications/oauth-jwt-lab`).

> This code is intentionally insecure - teaching material. Do not copy its verifier.

## The one switch

| `SECURE_MODE` | Behavior |
|---------------|----------|
| `false` (default) | the **broken** JWT verifier + missing object-level check - the attacks below work |
| `true` | the **fixed** verifier (pinned alg + strong key) + owner check - they all fail |

## JWT abuse (item 4)

The broken verifier lets the token's own `alg` header decide how it is checked, which
enables all three attacks. Forge a token with `{"sub":"bob","role":"admin"}` and reach
`GET /api/admin/users`:

| Attack | How | Fix |
|--------|-----|-----|
| **`alg:none`** | drop the signature, set `alg:none` - unsigned token accepted | reject `none`; use an `alg` allowlist |
| **weak HMAC** | HS256 signed with the guessable secret `secret` (crack a real `/login` token with `jwt_tool` / `hashcat`) | long random secret, or asymmetric keys |
| **RS256 -> HS256 confusion** | HS256 signed with the server's **RSA public key** (from `/public.pem` or `/jwks`) | pin the algorithm server-side |

The fixed verifier pins `algorithms=["HS256"]` with a strong secret, so `none`, the public
key, and the weak secret are all rejected.

## Authorization (item 5 - the authorization matrix)

| Method | Path | Check | In vuln mode |
|--------|------|-------|--------------|
| GET | `/api/docs/{id}` | object-level (owner) | **BOLA** - any user reads any doc |
| GET | `/api/admin/users` | function-level (role) | **BFLA** - reachable with a forged `role:admin` token |

Users **alice** and **bob** (password == username). alice owns `d-1`/`d-2`, bob owns `d-3`.
The caller's identity and role come from the (forgeable) JWT, so JWT abuse chains straight
into BFLA: forge `role:admin`, then call the admin route.

## OAuth (items 1-3 - redirect target)

The OAuth attacks run against the **lab Keycloak**; this service just hosts the callback:

| Path | Purpose |
|------|---------|
| GET `/callback` | shows the `?code` / `#fragment` the AS returned - use this URL as a Keycloak client's `redirect_uri` |
| GET `/redirect?to=` | a deliberate **open redirect**. With a loose (wildcard) Keycloak redirect-URI allowlist, an attacker sets `redirect_uri=.../redirect?to=https://evil` and the code is forwarded off-site. Fixed (same-origin only) in secure mode |

## Endpoints

| Method | Path | Notes |
|--------|------|-------|
| GET | `/health` | reports `secure_mode` |
| POST | `/login` | `{username,password}` -> a JWT (HS256) |
| GET | `/api/me` | the caller's `sub` / `role` from the token |
| GET | `/api/docs/{id}` | BOLA target |
| GET | `/api/admin/users` | BFLA target |
| GET | `/public.pem`, `/jwks` | the RSA public key (for the confusion attack) |
| GET | `/callback` | OAuth redirect target |
| GET | `/redirect?to=` | open redirect (for the loose-redirect-URI exercise) |

## Deploy (in your lab)

This runs **in the lab**, not on your laptop - same GitOps model as every other course
service (`vuln-api`, `dpop-rs`, ...):

1. **Fork** this repo into your org and enable Actions. Its CI builds the image to
   `ghcr.io/<your-org>/oauth-jwt-lab` and - with the org `DEPLOYMENT_PAT` - rewrites
   `applications/oauth-jwt-lab/deployment.yaml` in your `kse-labs-deployment` fork.
2. **Sync your `kse-labs-deployment` fork** so ArgoCD deploys `svc-oauth-jwt-lab`.

```bash
curl -sk https://oauth-jwt-lab.192.168.50.10.nip.io/health   # {"secure_mode":false,...}
```

Flip to the fixed build by setting `SECURE_MODE: "true"` in
`applications/oauth-jwt-lab/deployment.yaml` and pushing.

## Run the attacks

```bash
pip install pyjwt
python demo/attack.py --base https://oauth-jwt-lab.192.168.50.10.nip.io
```

It runs BOLA + the three JWT forgeries, then tells you to re-run against the
`SECURE_MODE=true` deployment to watch each one fail.

## Configuration (env)

| Var | Default |
|-----|---------|
| `SECURE_MODE` | `false` |
| `WEAK_HS_SECRET` | `secret` (the crackable HS256 key in vuln mode) |
| `STRONG_HS_SECRET` | random (used only in secure mode) |
