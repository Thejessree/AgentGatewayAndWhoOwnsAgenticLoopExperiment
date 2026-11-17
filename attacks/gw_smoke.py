#!/usr/bin/env python3
"""
gw_smoke.py -- quick checks that agentgateway is enforcing what gateway/config.yaml says.

    .venv/bin/python attacks/gw_smoke.py      # gateway on http://127.0.0.1:3000/mcp
"""
import asyncio
import subprocess
import sys

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

GATEWAY = "http://127.0.0.1:3000/mcp"
PY = sys.executable


def mint(*args: str) -> str:
    out = subprocess.run([PY, "idp/mint.py", "token", *args], capture_output=True, text=True, check=True)
    return out.stdout.strip()


async def session(token: str | None, client: str = "attacker-web-agent"):
    headers = {"Mcp-Client": client}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    http: httpx2.AsyncClient = create_mcp_http_client(headers=headers)
    return http, Client(streamable_http_client(GATEWAY, http_client=http), mode="2026-07-28")


async def check(label: str, token: str | None, tool: str | None = None, args: dict | None = None):
    http, client = await session(token)
    try:
        async with http, client as c:
            if tool is None:
                tools = await c.list_tools()
                print(f"  {label:<44} tools visible: {[t.name for t in tools.tools]}")
            else:
                res = await c.call_tool(tool, args or {})
                body = res.structured_content or (res.content[0].text if res.content else "")
                verdict = "ERROR" if res.is_error else "OK"
                print(f"  {label:<44} {verdict}: {body}")
    except Exception as e:  # transport / HTTP-level rejection
        # anyio wraps transport errors in ExceptionGroups; report the innermost cause.
        while isinstance(e, BaseExceptionGroup) and e.exceptions:
            e = e.exceptions[0]
        msg = str(e).splitlines()[0][:110] if str(e) else type(e).__name__
        print(f"  {label:<44} REJECTED: {type(e).__name__}: {msg}")


async def main():
    alice = mint("--sub", "alice", "--client", "alice-trusted-ide", "--scope", "secret:read")
    ci = mint("--sub", "ci-bot", "--client", "ci-pipeline", "--scope", "secret:read deploy:prod")

    print(f"\n=== agentgateway smoke test at {GATEWAY} ===\n")
    await check("1. no token, list tools", None)
    await check("2. alice (secret:read), list tools", alice)
    await check("3. alice (secret:read), read_secret", alice, "read_secret", {"handle": "handle-1007"})
    await check("4. alice (secret:read), deploy", alice, "deploy",
                {"handle": "handle-1007", "target": "payments-prod"})
    await check("5. ci-bot (deploy:prod), deploy", ci, "deploy",
                {"handle": "handle-1007", "target": "payments-prod"})
    print()


if __name__ == "__main__":
    asyncio.run(main())
