#!/usr/bin/env python3
"""
exp1_gateway.py -- Experiment 1: what does a gateway fix?

Runs every probe against agentgateway (:3000/mcp), which fronts the UNCHANGED
vulnerable server (:8181/mcp). Each probe records what was sent, what came back,
and whether the attack landed. Results go to traces/exp1_results.json for the
scorecard.

Needs running: vulnerable_server.py, scripts/run_gateway.sh (and Jaeger for traces).

    .venv/bin/python experiments/exp1_gateway.py
"""
import asyncio
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

ROOT = Path(__file__).resolve().parent.parent
GATEWAY = "http://127.0.0.1:3000/mcp"
VERSION = "2026-07-28"
RESULTS = ROOT / "traces" / "exp1_results.json"


@dataclass
class Probe:
    group: str
    name: str
    checklist: list[int]      # which of the 12 checklist questions this probe informs
    attack_landed: bool       # True = the bad thing happened
    status: int | None        # HTTP status from the gateway
    detail: str


PROBES: list[Probe] = []


def record(group, name, checklist, landed, status, detail):
    PROBES.append(Probe(group, name, checklist, landed, status, detail))
    mark = "LANDED " if landed else "blocked"
    print(f"  [{mark}] {name:<52} {status if status is not None else '-':>4}  {detail[:90]}")


def mint(sub, *extra, client="attacker-web-agent", scope="secret:read"):
    cmd = [sys.executable, "idp/mint.py", "token", "--sub", sub, "--client", client, "--scope", scope, *extra]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


# ---- raw stateless JSON-RPC, so we control every header and byte ------------------
async def raw(http, token, method, params=None, *, headers=None, name_header=None):
    params = dict(params or {})
    params["_meta"] = {"io.modelcontextprotocol/protocolVersion": VERSION,
                       "io.modelcontextprotocol/clientCapabilities": {}}
    h = {"Content-Type": "application/json",
         "Accept": "application/json, text/event-stream",
         "MCP-Protocol-Version": VERSION,
         "Mcp-Method": method,
         "Mcp-Client": "attacker-web-agent"}
    if method == "tools/call":
        h["Mcp-Name"] = name_header or params["name"]
    if token:
        h["Authorization"] = f"Bearer {token}"
    h.update(headers or {})
    r = await http.post(GATEWAY, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, headers=h)
    return r.status_code, parse(r.text)


def parse(text: str) -> dict:
    """Body may be plain JSON or an SSE stream; return the JSON-RPC message."""
    text = text.strip()
    if text.startswith(("event:", "data:", "id:")):
        for line in text.splitlines():
            if line.startswith("data:") and line[5:].strip():
                text = line[5:].strip()
                break
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text[:200]}


def tool_payload(msg: dict) -> dict:
    """Our server returns its answer as JSON inside the first text content block."""
    res = msg.get("result") or {}
    if res.get("structuredContent"):
        return res["structuredContent"]
    for block in res.get("content", []):
        if block.get("type") == "text":
            try:
                return json.loads(block["text"])
            except json.JSONDecodeError:
                return {"text": block["text"]}
    if "error" in msg:
        # JSON-RPC errors are objects; the gateway's HTTP-level 401 body is a plain string.
        err = msg["error"]
        return {"rpc_error": err.get("message") if isinstance(err, dict) else err}
    return msg


async def call(http, token, tool, args, **kw):
    status, msg = await raw(http, token, "tools/call", {"name": tool, "arguments": args}, **kw)
    return status, tool_payload(msg)


# ---- the probes ---------------------------------------------------------------------
async def tokyo_attacks(http):
    print("\n== A. The three Tokyo attacks, through the gateway ==")
    # The attacker is a legitimate user (alice) with a legitimate read-scoped token.
    alice = mint("alice")
    _, mine = await call(http, alice, "open_session", {"user": "alice"})
    handle = mine.get("handle", "")

    status, res = await call(http, alice, "read_secret", {"handle": "handle-2042"})
    record("tokyo", "1. guess Bob's handle, read his secret", [2, 5],
           "secret" in res and "bob" in res["secret"], status, json.dumps(res))

    status, res = await call(http, alice, "deploy", {"handle": handle, "target": "payments-prod"})
    record("tokyo", "2. read-scoped caller invokes deploy", [7],
           str(res.get("status", "")).startswith("LIVE"), status, json.dumps(res))

    # Handle minted for alice's IDE, replayed by the attacker's web agent (same user's token).
    ide_token = mint("alice", client="alice-trusted-ide")
    _, ide = await call(http, ide_token, "open_session", {"user": "alice"},
                        headers={"Mcp-Client": "alice-trusted-ide"})
    status, res = await call(http, alice, "read_secret", {"handle": ide.get("handle", "")})
    record("tokyo", "3. IDE's handle replayed from web agent", [2, 5],
           "secret" in res, status, json.dumps(res))


async def bad_tokens(http):
    print("\n== B. Bad tokens ==")
    cases = [
        ("no token at all", None),
        ("expired 1 hour ago", mint("alice-tokens", "--expired")),
        ("expired 90 s ago", mint("alice-tokens", "--expired-ago", "90")),
        # Clock-skew leeway: a token this fresh-expired may still be accepted.
        ("expired 30 s ago", mint("alice-tokens", "--expired-ago", "30")),
        ("no exp claim", mint("alice-tokens", "--no-exp")),
        ("nbf one hour in the future", mint("alice-tokens", "--nbf-future")),
        ("audience = some other server", mint("alice-tokens", "--aud", "http://other-server/mcp")),
        ("issuer = rogue IdP", mint("alice-tokens", "--iss", "http://evil-idp")),
        ("signed with an unknown key", mint("alice-tokens", "--rogue-key")),
        ("unsigned (alg=none)", mint("alice-tokens", "--alg-none")),
    ]
    for label, tok in cases:
        status, res = await call(http, tok, "read_secret", {"handle": "handle-1007"})
        record("tokens", f"token: {label}", [1], "secret" in res, status, json.dumps(res))


async def token_replay(http):
    print("\n== C. Stolen-token replay ==")
    # A valid token issued to alice's IDE, used verbatim by the attacker's agent.
    ide_token = mint("alice-replay", client="alice-trusted-ide")
    for i in (1, 2):
        status, res = await call(http, ide_token, "read_secret", {"handle": "handle-1007"},
                                 headers={"Mcp-Client": "attacker-web-agent"})
        record("replay", f"IDE token replayed by another client (use {i})", [1, 8],
               "secret" in res, status, json.dumps(res))


async def smuggling(http):
    print("\n== D. Header/body mismatch (request smuggling) ==")
    alice = mint("alice-smuggle")
    # Routing header says the harmless tool; JSON body calls the privileged one.
    status, res = await call(http, alice, "deploy", {"handle": "handle-1007", "target": "payments-prod"},
                             name_header="read_secret")
    record("smuggle", "Mcp-Name: read_secret, body calls deploy", [7, 12],
           str(res.get("status", "")).startswith("LIVE"), status, json.dumps(res))
    # And the reverse: header names the privileged tool, body calls the harmless one.
    status, res = await call(http, alice, "read_secret", {"handle": "handle-1007"}, name_header="deploy")
    record("smuggle", "Mcp-Name: deploy, body calls read_secret", [7, 12],
           False, status, json.dumps(res))


async def replay_writes(http):
    print("\n== E. Replayed write (idempotency) ==")
    ci = mint("ci-bot", client="ci-pipeline", scope="secret:read deploy:prod")
    outcomes = []
    for _ in range(2):
        _, res = await call(http, ci, "deploy", {"handle": "handle-9", "target": "billing-prod"},
                            headers={"Mcp-Client": "ci-pipeline"})
        outcomes.append(str(res.get("status", "")).startswith("LIVE"))
    record("idempotency", "same deploy request sent twice", [3],
           all(outcomes), 200, f"deploys executed: {sum(outcomes)} of 2")


def rate_limited(status: int, msg: dict) -> bool:
    # On MCP routes agentgateway does NOT answer 429: it returns HTTP 200 with a tool
    # error ("rate limit exceeded ..."). Checking status codes alone misses it.
    res = msg.get("result") or {}
    text = " ".join(b.get("text", "") for b in res.get("content", []))
    return status == 429 or (res.get("isError") and "rate limit" in text)


async def rate_limit(http):
    print("\n== F. Per-user rate limit (20/min keyed on jwt.sub) ==")
    noisy = mint("rl-noisy-user")
    limited = 0
    for _ in range(25):
        status, msg = await raw(http, noisy, "tools/call", {"name": "open_session", "arguments": {"user": "alice"}})
        limited += rate_limited(status, msg)
    record("ratelimit", "25 tool calls in a burst from one user", [11],
           limited == 0, 200, f"served {25 - limited}, rate-limited {limited} (HTTP 200 + isError, not 429)")
    quiet = mint("rl-quiet-user")
    status, msg = await raw(http, quiet, "tools/call", {"name": "open_session", "arguments": {"user": "bob"}})
    record("ratelimit", "a different user right after the burst", [11],
           rate_limited(status, msg), status,
           "throttled by someone else's burst" if rate_limited(status, msg) else "own bucket, served")


async def downgrade():
    print("\n== G. Protocol version through the gateway ==")
    tok = mint("alice-downgrade")
    for mode in ("2026-07-28", "legacy"):
        http = create_mcp_http_client(headers={"Authorization": f"Bearer {tok}"})
        try:
            async with http, Client(streamable_http_client(GATEWAY, http_client=http), mode=mode) as c:
                tools = await c.list_tools()
                # Accepting an older protocol is only a hole if policy stops applying to it.
                try:
                    res = await c.call_tool("deploy", {"handle": "handle-1007", "target": "payments-prod"})
                    bypass = not res.is_error and "LIVE" in (res.content[0].text if res.content else "")
                    deploy = "deploy ALLOWED" if bypass else "deploy denied"
                except Exception as e:
                    bypass, deploy = False, f"deploy denied ({str(e)[:40]})"
                record("downgrade", f"read-only client, mode={mode}", [12], bypass, 200,
                       f"negotiated {c.protocol_version}, tools={[t.name for t in tools.tools]}, {deploy}")
        except Exception as e:
            while isinstance(e, BaseExceptionGroup) and e.exceptions:
                e = e.exceptions[0]
            record("downgrade", f"read-only client, mode={mode}", [12], False, None, f"{type(e).__name__}: {e}")


async def main():
    print(f"=== Experiment 1: agentgateway in front of the vulnerable server ({GATEWAY}) ===")
    async with httpx2.AsyncClient(timeout=15) as http:
        await tokyo_attacks(http)
        await bad_tokens(http)
        await token_replay(http)
        await smuggling(http)
        await replay_writes(http)
        await rate_limit(http)
    await downgrade()

    RESULTS.parent.mkdir(exist_ok=True)
    RESULTS.write_text(json.dumps([asdict(p) for p in PROBES], indent=2) + "\n")
    landed = sum(p.attack_landed for p in PROBES)
    print(f"\n{len(PROBES)} probes, {landed} landed. Results: {RESULTS.relative_to(ROOT)}")


if __name__ == "__main__":
    asyncio.run(main())
