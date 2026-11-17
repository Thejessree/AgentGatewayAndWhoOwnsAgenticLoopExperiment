#!/usr/bin/env python3
"""
hardened_server.py -- the SAME stateless MCP server, defended.

Every hardening pattern from the talk, applied to the state handle:

  1. Handles are SIGNED (HMAC) and server-issued  -> unforgeable, unguessable
  2. Handles carry sub / scope / aud / iss / exp   -> self-describing token
  3. Signature + expiry verified on EVERY call     -> no replay
  4. aud checked against the calling client        -> no cross-client reuse
  5. scope re-checked per tool                      -> no capability confusion

Same tools as vulnerable_server.py, so the SAME attack.py runs against it --
and now fails four different ways.

Run:   .venv/bin/python servers/hardened_server.py      # http://127.0.0.1:8282/mcp
Then:  .venv/bin/python attacks/attack.py 8282
"""
import base64
import hashlib
import hmac
import json
import time

from mcp.server.mcpserver import Context, MCPServer

PORT = 8282
SERVER_ID = "mcp://devops.example"           # iss
SIGNING_KEY = b"rotate-me-per-deploy-please"  # demo only; use a KMS in prod
HANDLE_TTL = 300                              # seconds

USERS = {
    "alice": {"uid": "u-alice", "role": "developer"},
    "bob":   {"uid": "u-bob",   "role": "developer"},
}
SECRETS = {"u-alice": "alice's prod DB password: hunter2-alice",
           "u-bob":   "bob's prod DB password:  s3cr3t-bob-!!"}
DEPLOY_LOG = []

mcp = MCPServer("devops-hardened", version="1.0.0")


# ---- signed, self-describing handles ---------------------------------------
def mint_handle(sub, scope, aud):
    payload = {"sub": sub, "scope": scope, "aud": aud,
               "iss": SERVER_ID, "exp": int(time.time()) + HANDLE_TTL}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    body = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    sig = hmac.new(SIGNING_KEY, body.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{body}.{sig}"


def verify_handle(handle, *, calling_client, required_scope):
    """Returns (claims, None) if valid, else (None, reason)."""
    try:
        body, sig = handle.split(".", 1)
    except ValueError:
        return None, "malformed handle"
    expected = hmac.new(SIGNING_KEY, body.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        return None, "bad signature (forged or tampered)"     # kills forgery
    pad = "=" * (-len(body) % 4)
    claims = json.loads(base64.urlsafe_b64decode(body + pad))
    if claims.get("iss") != SERVER_ID:
        return None, "wrong issuer"
    if claims.get("exp", 0) < int(time.time()):
        return None, "handle expired"                          # kills replay
    if claims.get("aud") != calling_client:
        return None, f"audience mismatch (issued for {claims.get('aud')})"  # kills cross-client
    if required_scope not in claims.get("scope", []):
        return None, f"missing scope '{required_scope}'"       # kills capability confusion
    return claims, None


def client_of(ctx: Context) -> str:
    # NOTE: a plain header is client-supplied input, not proof of identity.
    # Good enough to show audience binding; experiment 1 replaces it with a
    # gateway-verified JWT subject.
    return (ctx.headers or {}).get("mcp-client", "unknown-client")


def log(ctx: Context, tool: str, result: dict) -> dict:
    verdict = "DENIED" if "error" in result else "ok"
    # telemetry: log the scope decision, never the handle contents.
    print(f"  [server] client={client_of(ctx):<18} tool={tool:<12} {verdict:<7} {result}")
    return result


# ---- tools -----------------------------------------------------------------
@mcp.tool()
def open_session(user: str, ctx: Context) -> dict:
    """Low-privilege tool. Mints a state handle for a user. (read scope)"""
    if user not in USERS:
        return log(ctx, "open_session", {"error": "unknown user"})
    # least privilege: this login only grants read scope, bound to THIS client.
    handle = mint_handle(USERS[user]["uid"], ["secret:read"], client_of(ctx))
    return log(ctx, "open_session", {"handle": handle})


@mcp.tool()
def read_secret(handle: str, ctx: Context) -> dict:
    """Read the caller's stored secret -- IF they present a handle. (read scope)"""
    claims, err = verify_handle(handle, calling_client=client_of(ctx), required_scope="secret:read")
    if err:
        return log(ctx, "read_secret", {"error": f"denied: {err}"})
    # ownership comes from the SIGNED subject, never from client-supplied ids.
    return log(ctx, "read_secret", {"secret": SECRETS[claims["sub"]]})


@mcp.tool()
def deploy(handle: str, target: str, ctx: Context) -> dict:
    """PRIVILEGED tool: push to production. Requires deploy scope."""
    claims, err = verify_handle(handle, calling_client=client_of(ctx), required_scope="deploy:prod")
    if err:
        return log(ctx, "deploy", {"error": f"denied: {err}"})
    DEPLOY_LOG.append(target)
    return log(ctx, "deploy", {"deployed": target, "status": "LIVE"})


if __name__ == "__main__":
    print(f"[hardened stateless MCP server] http://127.0.0.1:{PORT}/mcp")
    print("  handles are signed, scoped, audience-bound, and expiring.")
    mcp.run("streamable-http", host="127.0.0.1", port=PORT, stateless_http=True, json_response=True)
