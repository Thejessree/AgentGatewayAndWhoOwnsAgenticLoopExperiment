#!/usr/bin/env python3
"""
mint.py -- a tiny stand-in identity provider for the lab.

Plays the role Keycloak played in Lin Sun's keynote demo: it owns an RSA
signing key, publishes the public half as a JWKS, and issues JWTs that
agentgateway validates. It can also issue *bad* tokens on purpose, so the
experiments can check exactly which ones the gateway rejects.

    python idp/mint.py init                         # new RS256 key + keys/jwks.json
    python idp/mint.py serve                        # JWKS at http://127.0.0.1:9000/.well-known/jwks.json
    python idp/mint.py token --sub alice --client alice-trusted-ide --scope secret:read
    python idp/mint.py decode <token>               # show header + claims (no verification)

Bad-token switches on `token`: --expired, --ttl N, --aud URL, --iss URL,
--no-exp, --nbf-future, --rogue-key (signed by a key the gateway doesn't know),
--alg-none (unsigned).

Claims:
  iss     ISSUER
  aud     AUDIENCE (the gateway's MCP endpoint, RFC 8707 style)
  sub     the user
  azp     the client the token was issued to (e.g. alice-trusted-ide)
  scope   OAuth-style space-separated string
  scopes  same scopes as a list, so CEL rules can say `"deploy:prod" in jwt.scopes`
  iat/exp/jti
"""
import argparse
import base64
import json
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"
PRIVATE_KEY = KEYS / "signing-key.pem"
JWKS_FILE = KEYS / "jwks.json"
KID = "lab-key-1"

ISSUER = "http://127.0.0.1:9000"
AUDIENCE = "http://127.0.0.1:3000/mcp"
JWKS_PORT = 9000


def new_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def cmd_init(_args):
    KEYS.mkdir(exist_ok=True)
    key = new_rsa_key()
    PRIVATE_KEY.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    PRIVATE_KEY.chmod(0o600)
    pub = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                      "n": b64url_uint(pub.n), "e": b64url_uint(pub.e)}]}
    JWKS_FILE.write_text(json.dumps(jwks, indent=2) + "\n")
    print(f"wrote {PRIVATE_KEY.relative_to(ROOT)} and {JWKS_FILE.relative_to(ROOT)} (kid={KID})")


def load_key():
    if not PRIVATE_KEY.exists():
        sys.exit("no signing key yet: run `python idp/mint.py init` first")
    return serialization.load_pem_private_key(PRIVATE_KEY.read_bytes(), password=None)


def cmd_token(args):
    now = int(time.time())
    scopes = args.scope.split() if args.scope else []
    claims = {
        "iss": args.iss or ISSUER,
        "aud": args.aud or AUDIENCE,
        "sub": args.sub,
        "azp": args.client,
        "scope": " ".join(scopes),
        "scopes": scopes,
        "iat": now,
        "jti": uuid.uuid4().hex,
    }
    if not args.no_exp:
        if args.expired_ago is not None:
            claims["exp"] = now - args.expired_ago
        elif args.expired:
            claims["exp"] = now - 3600   # well past any clock-skew leeway
        else:
            claims["exp"] = now + args.ttl
    if args.nbf_future:
        claims["nbf"] = now + 3600

    if args.alg_none:
        token = jwt.encode(claims, key=None, algorithm="none")
    else:
        key = new_rsa_key() if args.rogue_key else load_key()
        token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})
    print(token)


def cmd_decode(args):
    header = jwt.get_unverified_header(args.token)
    claims = jwt.decode(args.token, options={"verify_signature": False})
    print(json.dumps({"header": header, "claims": claims}, indent=2))


def cmd_serve(args):
    if not JWKS_FILE.exists():
        sys.exit("no JWKS yet: run `python idp/mint.py init` first")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path != "/.well-known/jwks.json":
                self.send_error(404)
                return
            data = JWKS_FILE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    print(f"[lab idp] JWKS at http://127.0.0.1:{args.port}/.well-known/jwks.json")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="generate a new signing key and JWKS")

    t = sub.add_parser("token", help="issue a JWT")
    t.add_argument("--sub", required=True, help="user, e.g. alice")
    t.add_argument("--client", default="attacker-web-agent", help="azp: the client the token is issued to")
    t.add_argument("--scope", default="secret:read", help='space-separated, e.g. "secret:read deploy:prod"')
    t.add_argument("--ttl", type=int, default=300, help="seconds until exp (default 300)")
    t.add_argument("--aud", help=f"override audience (default {AUDIENCE})")
    t.add_argument("--iss", help=f"override issuer (default {ISSUER})")
    t.add_argument("--expired", action="store_true", help="exp one hour in the past")
    t.add_argument("--expired-ago", type=int, metavar="SECONDS", help="exp this many seconds in the past")
    t.add_argument("--no-exp", action="store_true", help="omit exp entirely")
    t.add_argument("--nbf-future", action="store_true", help="not valid for another hour")
    t.add_argument("--rogue-key", action="store_true", help="sign with a key the gateway has never seen")
    t.add_argument("--alg-none", action="store_true", help="unsigned token (alg=none)")

    d = sub.add_parser("decode", help="print header and claims without verifying")
    d.add_argument("token")

    s = sub.add_parser("serve", help="serve the JWKS over HTTP")
    s.add_argument("--port", type=int, default=JWKS_PORT)

    args = p.parse_args()
    {"init": cmd_init, "token": cmd_token, "decode": cmd_decode, "serve": cmd_serve}[args.cmd](args)


if __name__ == "__main__":
    main()
