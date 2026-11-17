#!/usr/bin/env python3
"""
vulnerable_server.py -- a DELIBERATELY INSECURE stateless MCP server.

Real MCP this time: MCP Python SDK 2.3.0, protocol 2026-07-28, stateless
Streamable HTTP. Same three tools and the same bugs as the Tokyo demo
("MCP 2026-07-28 Under the Microscope", AGNTCon + MCPCon Japan 2026).

There is NO session. Cross-call state is a server-issued "handle" that the
client passes back as an ordinary tool argument. The handle is just data:
"handle-<seq>". It is:
  - guessable           (sequential, no signature)
  - not bound to a user (server trusts whatever id is inside it)
  - not scoped          (a read tool and a deploy tool accept the same handle)
  - not audience-bound  (any client may replay it)
  - never expires

Run:   .venv/bin/python servers/vulnerable_server.py     # http://127.0.0.1:8181/mcp
Then:  .venv/bin/python attacks/attack.py                 # drives the exploit
"""
from mcp.server.mcpserver import Context, MCPServer

PORT = 8181

# ---- fake backend data -----------------------------------------------------
USERS = {
    "alice": {"seq": 1007, "role": "developer"},
    "bob":   {"seq": 2042, "role": "developer"},
}
SECRETS = {
    1007: "alice's prod DB password: hunter2-alice",
    2042: "bob's prod DB password:  s3cr3t-bob-!!",   # <-- attacker wants this
}
DEPLOY_LOG = []

mcp = MCPServer("devops-vulnerable", version="1.0.0")


def client_of(ctx: Context) -> str:
    # The server ignores the caller's identity entirely; we only read it to log it.
    return (ctx.headers or {}).get("mcp-client", "unknown-client")


def log(ctx: Context, tool: str, result: dict) -> dict:
    # Did a bearer token reach us? Behind the gateway it should not (no token passthrough).
    token = "token=PASSED-THROUGH" if "authorization" in (ctx.headers or {}) else "token=none"
    print(f"  [server] client={client_of(ctx):<18} {token:<20} tool={tool:<12} -> {result}")
    return result


# ---- the tools this MCP server exposes -------------------------------------
@mcp.tool()
def open_session(user: str, ctx: Context) -> dict:
    """Low-privilege tool. Mints a state handle for a user. (read scope)"""
    if user not in USERS:
        return log(ctx, "open_session", {"error": "unknown user"})
    # VULN: handle is guessable and carries the user id in the clear.
    handle = f"handle-{USERS[user]['seq']}"
    return log(ctx, "open_session", {"handle": handle, "note": "pass this handle to other tools"})


@mcp.tool()
def read_secret(handle: str, ctx: Context) -> dict:
    """Read the caller's stored secret -- IF they present a handle. (read scope)"""
    # VULN: trusts the id embedded in the handle. No signature, no ownership
    #       check, no session to compare against. Classic stateless IDOR.
    try:
        seq = int(handle.split("-")[1])
    except (IndexError, ValueError):
        return log(ctx, "read_secret", {"error": "bad handle"})
    if seq not in SECRETS:
        return log(ctx, "read_secret", {"error": "no such record"})
    return log(ctx, "read_secret", {"secret": SECRETS[seq]})


@mcp.tool()
def deploy(handle: str, target: str, ctx: Context) -> dict:
    """PRIVILEGED tool: push to production. Should require deploy scope."""
    # VULN: capability confusion. The privileged tool accepts the SAME handle
    #       shape the read tool minted. It never checks that the handle was
    #       granted a deploy scope. A read handle == a deploy handle.
    if not handle.startswith("handle-"):
        return log(ctx, "deploy", {"error": "missing handle"})
    DEPLOY_LOG.append(target)
    return log(ctx, "deploy", {"deployed": target, "status": "LIVE IN PRODUCTION"})


if __name__ == "__main__":
    print(f"[vulnerable stateless MCP server] http://127.0.0.1:{PORT}/mcp")
    print("  no sessions. handles are trusted as plain arguments. this is the bug.")
    mcp.run("streamable-http", host="127.0.0.1", port=PORT, stateless_http=True, json_response=True)
