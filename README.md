# MCP Gateway Lab

Two experiments that grew out of AGNTCon + MCPCon Japan 2026 (Tokyo, Sept 10-11):

1. **What does a gateway fix?** Put [agentgateway](https://agentgateway.dev/) in front of a
   deliberately vulnerable stateless MCP server and score each of the 12 questions from the
   talk's defender's checklist: fixed by the gateway, still the server's job, or uncovered.
2. **The agentic whodunit.** A Gemini-driven agent works a support ticket through the gateway,
   one tool result carries a planted instruction, and the question is whether the traces alone
   show where it went wrong, and who should have stopped it.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt   # mcp 2.3.0, google-genai, OpenTelemetry SDK
```

Put your Gemini key in `.env` (git-ignored) as `GEMINI_API_KEY=...`. Never commit it.

Gateway and trace viewer (macOS arm64, checksums verified, no Docker):

```bash
./scripts/install_tools.sh     # agentgateway v1.7.0 -> bin/agentgateway-bin, Jaeger 2.22.0 -> bin/jaeger-bin
./bin/jaeger-bin               # UI on http://127.0.0.1:16686, OTLP/HTTP on :4318
```

## Lab identity provider

`idp/mint.py` stands in for Keycloak: an RS256 key, a JWKS, and JWTs for the gateway to validate.
It can also mint bad tokens on purpose, so the experiments can check exactly which ones the
gateway rejects. The key lives in `keys/` (git-ignored).

```bash
.venv/bin/python idp/mint.py init      # keys/signing-key.pem + keys/jwks.json
.venv/bin/python idp/mint.py serve     # http://127.0.0.1:9000/.well-known/jwks.json
.venv/bin/python idp/mint.py token --sub alice --client alice-trusted-ide --scope secret:read
.venv/bin/python idp/mint.py token --sub ci-bot --client ci-pipeline --scope "secret:read deploy:prod"
```

| Claim | Value |
|-------|-------|
| `iss` | `http://127.0.0.1:9000` |
| `aud` | `http://127.0.0.1:3000/mcp` (the gateway's MCP endpoint) |
| `sub` | the user |
| `azp` | the client the token was issued to |
| `scope` / `scopes` | space-separated string / the same as a list for CEL rules |
| `exp` | 300 s by default |

Bad-token switches: `--expired`, `--no-exp`, `--nbf-future`, `--aud`, `--iss`, `--rogue-key`,
`--alg-none`. Checked against PyJWT with the published JWKS: the good tokens verify and each
bad one fails for its intended reason. Whether **the gateway** rejects them too is part of
experiment 1.

## The gateway

`gateway/config.yaml` puts agentgateway v1.7.0 in front of the **unchanged** vulnerable server:

```
client --(JWT)--> agentgateway :3000/mcp --(token stripped)--> vulnerable_server :8181/mcp
```

| Policy | What it enforces |
|--------|------------------|
| `mcpAuthentication` (strict) | Valid RS256 JWT on every call: `iss`, `aud`, `exp`, `sub` required |
| `mcpAuthorization` | `open_session` / `read_secret` need `secret:read`; `deploy` needs `deploy:prod` |
| `localRateLimit` | 20 requests per minute, one bucket per `jwt.sub` |
| `frontendPolicies.tracing` | Every request traced to Jaeger over OTLP/HTTP |

```bash
./bin/jaeger-bin &                                   # http://127.0.0.1:16686
.venv/bin/python servers/vulnerable_server.py &
./scripts/run_gateway.sh &                           # http://127.0.0.1:3000/mcp
.venv/bin/python attacks/gw_smoke.py
```

Smoke test results:

| Request | Result |
|---------|--------|
| No token | 401, `no bearer token found` |
| Alice (`secret:read`) lists tools | sees `open_session`, `read_secret` only |
| Alice reads her secret | allowed |
| Alice calls `deploy` | rejected: `unknown resource` (the tool is hidden, not "forbidden") |
| ci-bot (`deploy:prod`) calls `deploy` | allowed |

### Notes from setting it up

- **The gateway writes a secret into its own config file.** On first start agentgateway adds an
  auto-generated `config.session.key` to the file it was started with. If that file is tracked,
  the key ends up in git. `scripts/run_gateway.sh` runs a git-ignored copy instead.
- **The docs disagree; the schema doesn't.** The docs pages contradict each other on the default
  auth mode and the tracing config. The JSON schema (`https://agentgateway.dev/schema/config`)
  and `--validate-only` settle it: `strict` is the default, and `config.tracing` is deprecated in
  favour of `frontendPolicies.tracing`.
- **Unauthorized tools disappear.** Alice never sees `deploy` in `tools/list`, and calling it
  anyway returns `unknown resource`, so an attacker can't even confirm the tool exists.

## Experiment 1 results

```bash
./scripts/lab.sh start                          # Jaeger, vulnerable server, gateway (PID-tracked)
.venv/bin/python experiments/exp1_gateway.py    # 20 probes -> traces/exp1_results.json
./scripts/lab.sh stop
```

**Scorecard against the talk's 12-question checklist: [experiments/exp1_scorecard.md](experiments/exp1_scorecard.md)**
(3 fixed by the gateway, 2 partly, 2 still the server's job, 1 not covered, 4 not tested).

22 probes against agentgateway v1.7.0 fronting the unchanged vulnerable server. **6 landed.**
Two full runs a minute apart gave identical verdicts.

| Probe | Outcome | Why |
|-------|---------|-----|
| Tokyo 1: guess Bob's handle | **landed** | The handle is a tool *argument*; `mcpAuthorization` rules can't see arguments |
| Tokyo 2: read-scoped caller calls `deploy` | blocked | Scope rule; `deploy` is hidden and returns `unknown resource` |
| Tokyo 3: IDE's handle replayed by web agent | **landed** | Same user, valid token; the gateway has no idea what a handle is |
| 10 bad tokens (none, expired 1 h / 90 s, no `exp`, future `nbf`, wrong `aud`, wrong `iss`, unknown key, `alg=none`) | all blocked | 401 for each |
| Token expired **30 s** ago | **landed** | 60 s clock-skew leeway on `exp` (see below) |
| Stolen token replayed from another client (x2) | **landed** | Bearer token, no client binding, `jti` not enforced |
| Header/body mismatch, both directions | blocked | Gateway returns `Mcp-Name header/body mismatch`; nothing reaches the server |
| Same `deploy` sent twice | **landed** | Both execute; no idempotency anywhere |
| 25-call burst from one user | blocked | 20 served, 5 rate-limited; a second user right after is unaffected |
| Legacy-protocol client (`2025-11-25`) | blocked | Older protocol accepted, but the same policies still apply |
| Token passthrough | blocked | The server never saw an `Authorization` header |

### Finding: MCP rate limits don't look like rate limits

On a plain HTTP route an over-limit request gets **HTTP 429**. On an MCP route it gets
**HTTP 200** with a tool error in the body:

```json
{"result": {"content": [{"type": "text", "text": "rate limit exceeded (retry after 56s; limit 2, remaining 0)"}], "isError": true}}
```

That is the MCP-native way to fail a tool call, and the call never reaches the server. But any
monitoring or test that counts 429s sees zero, and an agent may treat it as an ordinary tool
failure and retry. (The first version of this experiment fell for exactly that and reported the
limit as "not enforced".) `gateway/repro/ratelimit-http-vs-mcp.yaml` shows both side by side.

### Finding: expired tokens work for another minute

Tokens are accepted up to 60 s after `exp`: 59 s accepted, 61 s rejected, three runs out of
three. That's a standard clock-skew allowance, but it extends every stolen token's life by a
minute, and `jwtValidationOptions` has no setting for it.

### Remote rate limiting works too

`remoteRateLimit` calls an Envoy-compatible rate limit service over gRPC. `ratelimit/server.py`
is a ~100-line one (fixed window per descriptor, no Redis). Same behaviour as the local limiter:
over-limit MCP calls return 200 + `isError` and never reach the server.

```bash
.venv/bin/python ratelimit/server.py --limit 20 --window 60    # gRPC on 127.0.0.1:8081
```

```yaml
    remoteRateLimit:
      host: 127.0.0.1:8081
      domain: lab
      descriptors:
      - entries:
        - key: user
          value: jwt.sub
```

## Step 0: the Tokyo demo on real MCP

The conference demo used an MCP-style HTTP protocol. Here it is ported to the real thing:
MCP Python SDK 2.3.0, protocol `2026-07-28`, stateless Streamable HTTP.

```bash
./run_step0.sh
```

| File | Role |
|------|------|
| `servers/vulnerable_server.py` | Trusts handles as plain arguments. `:8181/mcp` |
| `servers/hardened_server.py`   | Signed, scoped, audience-bound, expiring handles. `:8282/mcp` |
| `attacks/attack.py`            | MCP client running the three attacks. Takes a port or a full URL. |

Result: all three attacks land on `:8181` and are denied on `:8282` (malformed handle,
missing scope `deploy:prod`, audience mismatch).

### Notes from the port

- **No handshake, no session.** A single raw `curl` with `tools/call` reads Bob's secret.
- **Every request reintroduces itself.** A request without
  `io.modelcontextprotocol/clientCapabilities` in `_meta` is rejected with `-32602`.
- **The client identity is a header, and headers are not identity.** The SDK's own docstring
  for `Context.headers` says: "Headers are client-supplied input - never treat one as an
  identity assertion." The hardened server's audience check is only as strong as that header,
  which is the gap experiment 1 tests a gateway-verified JWT against.
