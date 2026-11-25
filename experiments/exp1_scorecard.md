# Experiment 1 scorecard: what does a gateway fix?

agentgateway v1.7.0 in front of the **unchanged** vulnerable server, scored against the 12
questions of the defender's checklist from *MCP 2026-07-28 Under the Microscope*
(AGNTCon + MCPCon Japan 2026). Evidence: 22 probes in `traces/exp1_results.json` (two identical
runs) plus the gateway's spans in Jaeger.

**Bottom line: the gateway fixed 3 of 12 outright and 2 partly. Everything that lives in a tool's
arguments (handles, tenant ownership, duplicate writes) stayed the server's job.**

| # | Checklist question | Verdict | Evidence |
|---|--------------------|---------|----------|
| 1 | Auth + audience on every call | **Fixed by gateway** | 10 bad tokens all 401. Caveat: 60 s leeway after `exp` |
| 2 | Handles bound, expiring, signed | **Server's job** | Tokyo 1 and 3 landed; the gateway can't see or verify handles |
| 3 | Idempotency keys on writes | **Not covered** | Same `deploy` sent twice, both executed |
| 4 | `requestState` sealed and replay-bounded | Not tested | Our server doesn't use multi-round-trip requests |
| 5 | Tenant isolation per request | **Server's job** | Valid token for alice read Bob's secret (Tokyo 1) |
| 6 | `cacheScope` reviewed | Not tested | No cacheable results in our server |
| 7 | Minimal scopes, reader/writer split | **Fixed by gateway** | Read-scoped `deploy` blocked; header/body smuggling blocked |
| 8 | Client allowlists, no token passthrough | **Partly** | Token never reached the server; stolen token replayed from another client worked |
| 9 | Tool manifests pinned and diffed | Not tested | Gateway hides unauthorized tools but doesn't pin descriptions |
| 10 | Trifecta: one leg removed | Not tested | Experiment 2 (`exp2_*`) |
| 11 | Traces on every tool call | **Fixed by gateway** | Every call traced with `jwt.sub`, tool, outcome; never handle contents. Caveat: no handle ids, so no same-handle-across-clients alert |
| 12 | Downgrade deliberate, or refused | **Partly** | Legacy `2025-11-25` client accepted silently, but policies still applied |

Tally of the 8 questions this experiment could measure: **3 fixed, 2 partly, 2 server's job,
1 not covered.** 4 were out of scope.

---

## The details

### 1. Auth + audience on every call: fixed by gateway

`mcpAuthentication` in `strict` mode rejected every bad token with 401: no token, expired 1 h
and 90 s ago, no `exp`, `nbf` in the future, audience of another server, rogue issuer, unknown
signing key, `alg=none`. The server code never changed.

Caveat: a token that expired **30 s** ago was accepted. The gateway allows 60 s of clock skew on
`exp` (59 s accepted, 61 s rejected, three runs out of three), and `jwtValidationOptions` has no
setting for it. Short-lived tokens are effectively a minute longer than they say.

### 2. Handles bound, expiring, signed: server's job

Tokyo attack 1 (guess `handle-2042`, read Bob's secret) and attack 3 (replay the IDE's handle
from the web agent) both landed through the gateway. The handle is a tool argument. The gateway
checks *who* is calling and *which tool*, not *what the arguments mean*. Its `mcpAuthorization`
rules can't read arguments at all; route-level rules can (`mcp.tool.arguments`), but CEL can't
verify an HMAC. Signing, scoping and binding handles stays in the server, as in
`servers/hardened_server.py`.

### 3. Idempotency keys on writes: not covered

The ci-bot sent the same `deploy` twice; both ran. Neither the gateway nor MCP core has a notion
of a duplicate request. This one needs an idempotency key in the tool's arguments, checked by
the server.

### 5. Tenant isolation per request: server's job

The gateway knows exactly who is calling (`jwt.sub=alice` is on every span), but the server
never finds out: the token is stripped before forwarding (good, see #8), and nothing else carries
the identity. So the server can't check that `handle-2042` belongs to the caller. A gateway can
*carry* identity to the server, for example by setting a header from `jwt.sub`, but the
ownership check itself has to happen where the data is. Not tested here.

### 7. Minimal scopes, reader/writer split: fixed by gateway

Three CEL rules gave each tool its own scope. Results:

- A read-scoped token never sees `deploy` in `tools/list`, and calling it returns
  `unknown resource`, so an attacker can't even confirm the tool exists.
- A legacy-protocol client got the same filtered list and the same denial.
- **Smuggling** (Mcp-Name header says `read_secret`, JSON body calls `deploy`, and the reverse)
  was rejected by the gateway with `Mcp-Name header/body mismatch`. Nothing reached the server.

### 8. Client allowlists, no token passthrough: partly

- **No passthrough: fixed.** The server logs whether an `Authorization` header arrives. Across
  every run it never did.
- **Client binding: not fixed.** A token issued to `alice-trusted-ide` worked when replayed by
  `attacker-web-agent`, twice. It's a bearer token: whoever holds it is alice. A rule on
  `jwt.azp` wouldn't help, because a stolen token carries the victim's `azp`. Closing this needs
  sender-constrained tokens (DPoP or mTLS), which this setup doesn't have. `jti` isn't enforced
  either, so a token can be replayed until it expires (plus the 60 s).

### 11. Traces on every tool call: fixed by gateway

Every request became a span in Jaeger with `jwt.sub`, `mcp.method.name`, `gen_ai.tool.name`,
`mcp.target`, the status code and a `reason` on failures (`JwtAuth`, `Authorization`, `MCP`,
`RateLimit`). No span carried tool arguments, so handle contents never reach the logs, as the
checklist asks.

The flip side: because the gateway never sees handles, it can't raise the checklist's
"same handle across clients" alert. That one also stays with the server.

**Rate limits** (not a checklist question, but they live here): 25 calls from one user, 20
served and 5 blocked; a second user unaffected. An over-limit MCP call returns **HTTP 200 with a
tool error**, not 429. The span still says `reason=RateLimit`, so alert on `reason`, not on
status codes.

### 12. Downgrade deliberate, or refused: partly

A client forcing the legacy handshake negotiated `2025-11-25` and was let in without complaint,
so the downgrade is not refused. In this setup it didn't matter: authentication, scopes and tool
filtering applied identically. The smuggling half of this question (header vs body) is covered
under #7. Whether a dual-era *server* reopens old holes when downgraded is a server question,
not tested here.

### Not tested here

- **4. `requestState`**: our server doesn't use multi-round-trip requests. The SDK ships
  `AESGCMRequestStateCodec` and `RequestStateSecurity` for sealing it server-side; the gateway
  can't help because the state travels inside the request body.
- **6. `cacheScope`**: our server returns no cacheable results.
- **9. Manifest pinning**: the gateway filters tools by policy but doesn't hash or diff their
  descriptions. A rug-pull test would need a server that changes its tool descriptions.
- **10. Trifecta**: that's experiment 2 (`exp2_*`).

---

## What this means

A gateway is very good at everything that can be decided from **who** is calling and **which**
tool: authentication, scopes, smuggling, token stripping, tracing, rate limits. It cannot fix
anything that depends on **what the arguments mean**: whose handle this is, whether this deploy
already happened, whether this record belongs to this tenant.

The Tokyo talk's line was "every state handle is a security token: sign it, scope it, bind it,
expire it, re-verify it on every call." The gateway does all five for the *bearer token*. Nobody
does them for the *handle* except the server.
