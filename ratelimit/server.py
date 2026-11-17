#!/usr/bin/env python3
"""
server.py -- a tiny Envoy-compatible rate limit service for agentgateway's `remoteRateLimit`.

Stands in for envoyproxy/ratelimit (which needs Redis). One fixed window per
(domain, descriptor) pair: by default 20 hits per 60 s, so a descriptor of
`user = jwt.sub` gives every user their own bucket.

    .venv/bin/python ratelimit/server.py                  # gRPC on 127.0.0.1:8081
    .venv/bin/python ratelimit/server.py --limit 5 --window 30

Regenerate the stubs after editing rls.proto:
    .venv/bin/python -m grpc_tools.protoc -I ratelimit --python_out=ratelimit/gen \
        --grpc_python_out=ratelimit/gen ratelimit/rls.proto
"""
import argparse
import sys
import threading
import time
from concurrent import futures
from pathlib import Path

import grpc

sys.path.insert(0, str(Path(__file__).resolve().parent / "gen"))
import rls_pb2  # noqa: E402
import rls_pb2_grpc  # noqa: E402

Code = rls_pb2.RateLimitResponse.Code


class FixedWindow:
    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self.counts: dict[tuple, tuple[float, int]] = {}
        self.lock = threading.Lock()

    def hit(self, key: tuple, n: int) -> tuple[bool, int]:
        """Count n hits against key. Returns (over_limit, remaining)."""
        now = time.monotonic()
        with self.lock:
            start, count = self.counts.get(key, (now, 0))
            if now - start >= self.window:
                start, count = now, 0
            count += n
            self.counts[key] = (start, count)
        return count > self.limit, max(self.limit - count, 0)


class RateLimitService(rls_pb2_grpc.RateLimitServiceServicer):
    def __init__(self, window: FixedWindow):
        self.window = window

    def ShouldRateLimit(self, request, context):
        hits = request.hits_addend or 1
        resp = rls_pb2.RateLimitResponse(overall_code=Code.OK)
        for d in request.descriptors:
            entries = tuple((e.key, e.value) for e in d.entries)
            over, remaining = self.window.hit((request.domain, entries), hits)
            resp.statuses.add(code=Code.OVER_LIMIT if over else Code.OK, limit_remaining=remaining)
            if over:
                resp.overall_code = Code.OVER_LIMIT
            label = " ".join(f"{k}={v}" for k, v in entries) or "(no entries)"
            verdict = "OVER_LIMIT" if over else "ok"
            print(f"  [ratelimit] domain={request.domain} {label:<28} {verdict:<10} remaining={remaining}", flush=True)
        return resp


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--limit", type=int, default=20, help="hits allowed per window per descriptor")
    p.add_argument("--window", type=float, default=60, help="window length in seconds")
    args = p.parse_args()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    rls_pb2_grpc.add_RateLimitServiceServicer_to_server(RateLimitService(FixedWindow(args.limit, args.window)), server)
    server.add_insecure_port(f"127.0.0.1:{args.port}")
    server.start()
    print(f"[ratelimit] Envoy RLS v3 on 127.0.0.1:{args.port}: {args.limit} hits / {args.window:g}s per descriptor",
          flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    main()
