#!/usr/bin/env bash
HERE=$(cd "$(dirname "$0")" && pwd)
[ -f "$HERE/build/compose.yaml" ] && FABRIC_VERSION=${FABRIC_VERSION:-2.5.16} docker compose -f "$HERE/build/compose.yaml" -p custody down -v >/dev/null 2>&1
docker rm -f $(docker ps -aq --filter name=dev-peer) >/dev/null 2>&1 || true
docker rmi -f $(docker images -q --filter reference='dev-peer*') >/dev/null 2>&1 || true
rm -rf "$HERE/build"; echo NETWORK_DOWN
