"""
MCP client plumbing shared by the agent and test scripts: a stateless 2026-07-28
connection through the gateway, with a bearer token and W3C trace context.

The SDK already puts `traceparent` in each request's `_meta` (SEP-414), which the
MCP server reads. The gateway reads trace context from HTTP headers instead, so
we also inject it there on every request; that's what joins the gateway's span
to the same trace.
"""
import contextlib
import json

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from opentelemetry.propagate import inject

GATEWAY = "http://127.0.0.1:3000/mcp"


async def _inject_trace_headers(request: httpx2.Request) -> None:
    carrier: dict[str, str] = {}
    inject(carrier)
    for k, v in carrier.items():
        request.headers[k] = v


@contextlib.asynccontextmanager
async def connect(token: str, url: str = GATEWAY):
    http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
    http.event_hooks["request"].append(_inject_trace_headers)
    async with http, Client(streamable_http_client(url, http_client=http), mode="2026-07-28") as client:
        yield client


def result_payload(res) -> object:
    """A tool result as plain JSON: structured content if present, else parsed text."""
    if res.structured_content is not None:
        sc = res.structured_content
        return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc
    text = "".join(getattr(b, "text", "") for b in res.content)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"text": text}
