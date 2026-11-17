#!/usr/bin/env bash
# Download agentgateway and Jaeger (macOS arm64) into bin/, verifying SHA-256
# against each project's published checksums. No Docker, no Kubernetes.
set -euo pipefail
cd "$(dirname "$0")/.."

AGW_VERSION=v1.7.0
JAEGER_VERSION=2.22.0

mkdir -p bin/agentgateway bin/jaeger

# --- agentgateway: single binary + .sha256 -----------------------------------
(
  cd bin/agentgateway
  base=https://github.com/agentgateway/agentgateway/releases/download/$AGW_VERSION
  curl -sSLf -o agentgateway-darwin-arm64        "$base/agentgateway-darwin-arm64"
  curl -sSLf -o agentgateway-darwin-arm64.sha256 "$base/agentgateway-darwin-arm64.sha256"
  want=$(awk '{print $1}' agentgateway-darwin-arm64.sha256)
  got=$(shasum -a 256 agentgateway-darwin-arm64 | awk '{print $1}')
  [ "$want" = "$got" ] || { echo "agentgateway checksum MISMATCH"; exit 1; }
  chmod +x agentgateway-darwin-arm64
  echo "agentgateway $AGW_VERSION verified"
)

# --- jaeger: tarball; checksum file covers the binaries inside it ------------
(
  cd bin/jaeger
  base=https://github.com/jaegertracing/jaeger/releases/download/v$JAEGER_VERSION
  name=jaeger-$JAEGER_VERSION-darwin-arm64
  curl -sSLf -o "$name.tar.gz"         "$base/$name.tar.gz"
  curl -sSLf -o "$name.sha256sum.txt"  "$base/$name.sha256sum.txt"
  tar -xzf "$name.tar.gz" && rm "$name.tar.gz"
  want=$(grep "/jaeger$" "$name.sha256sum.txt" | awk '{print $1}')
  got=$(shasum -a 256 "$name/jaeger" | awk '{print $1}')
  [ "$want" = "$got" ] || { echo "jaeger checksum MISMATCH"; exit 1; }
  echo "jaeger $JAEGER_VERSION verified"
)

ln -sf agentgateway/agentgateway-darwin-arm64 bin/agentgateway-bin
ln -sf "jaeger/jaeger-$JAEGER_VERSION-darwin-arm64/jaeger" bin/jaeger-bin
