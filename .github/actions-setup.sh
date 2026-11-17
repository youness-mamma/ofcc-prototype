#!/usr/bin/env bash
# Shared runner setup: Fabric binaries/images (pinned), MinIO built from pinned source, bench binary.
set -euo pipefail
mkdir -p fabric && cd fabric
curl -sSLo install-fabric.sh "https://raw.githubusercontent.com/hyperledger/fabric/${INSTALL_SCRIPT_SHA}/scripts/install-fabric.sh"
chmod +x install-fabric.sh
./install-fabric.sh -f "$FABRIC_VERSION" -c "$FABRIC_CA_VERSION" docker binary >/dev/null
cd ..
echo "$PWD/fabric/bin" >> "$GITHUB_PATH"
echo "FABRIC_CFG_DIR=$PWD/fabric/config" >> "$GITHUB_ENV"
if [ ! -x minio-bin/minio ]; then GOBIN=$PWD/minio-bin go install "github.com/minio/minio@${MINIO_RELEASE}"; fi
mkdir -p minio-data
MINIO_ROOT_USER=ofccadmin MINIO_ROOT_PASSWORD=ofccadmin-secret nohup ./minio-bin/minio server "$PWD/minio-data" --address 127.0.0.1:9000 > minio.log 2>&1 &
for i in $(seq 1 30); do curl -sf http://127.0.0.1:9000/minio/health/live && break; sleep 1; done
(cd client && go build -o ../bin/bench ./cmd/bench)
echo "setup done"
