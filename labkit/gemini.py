"""
Gemini plumbing shared by the lab's agents: API key from .env, MCP tools as
function declarations, and one model turn with backoff.
"""
import asyncio
import os
import sys
from pathlib import Path

from google import genai
from google.genai import errors as genai_errors
from google.genai import types

ROOT = Path(__file__).resolve().parent.parent


def load_env():
    env = ROOT / ".env"
    if not env.exists():
        sys.exit("no .env: put GEMINI_API_KEY=... in it first")
    for line in env.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def gemini_client() -> genai.Client:
    load_env()
    # v1beta: older models (2.5) reject function calling on the SDK's default v1 endpoint.
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"],
                        http_options=types.HttpOptions(api_version="v1beta"))


def declarations(tools) -> list[types.FunctionDeclaration]:
    return [types.FunctionDeclaration(name=t.name, description=t.description or "",
                                      parameters_json_schema=t.input_schema)
            for t in tools]


async def generate(client, model, contents, config, retries=4):
    """One model turn, with backoff on rate limits / transient server errors."""
    for attempt in range(retries):
        try:
            return await client.aio.models.generate_content(model=model, contents=contents, config=config)
        except (genai_errors.ServerError, genai_errors.ClientError) as e:
            code = getattr(e, "code", None)
            if code not in (429, 500, 503) or attempt == retries - 1:
                raise
            await asyncio.sleep(2 ** attempt * 5)
