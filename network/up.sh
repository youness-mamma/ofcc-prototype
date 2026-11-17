#!/usr/bin/env bash
# Bring up an N-org Fabric network (1 peer/org, 3 Raft orderers), create channel "custody",
# deploy the custody chaincode. Requires: Fabric binaries on PATH, FABRIC_CFG_DIR = fabric-samples/config.
# Usage: up.sh <n_orgs> <batch_timeout> <max_message_count>
set -euo pipefail
N=${1:-4}; BT=${2:-1s}; MMC=${3:-100}
HERE=$(cd "$(dirname "$0")" && pwd); B=$HERE/build; CH=custody; CC=custody
: "${FABRIC_VERSION:=2.5.16}"; export FABRIC_VERSION
rm -rf "$B"; mkdir -p "$B/peercfg"
python3 "$HERE/gen.py" "$N" "$BT" "$MMC" "$B"
cp "$FABRIC_CFG_DIR/core.yaml" "$B/peercfg/"
cd "$B"
cryptogen generate --config=crypto-config.yaml --output=crypto >/dev/null
configtxgen -configPath "$B" -profile CustodyChannel -outputBlock "$B/$CH.block" -channelID $CH 2>/dev/null
docker compose -f compose.yaml -p custody up -d 2>&1 | tail -n 2

OCA=$B/crypto/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
i=0
for ap in 7053 8053 9053; do
  o=orderer$i; d=$B/crypto/ordererOrganizations/example.com/orderers/$o.example.com/tls
  for t in $(seq 1 30); do
    osnadmin channel join --channelID $CH --config-block $CH.block -o localhost:$ap --ca-file "$OCA" \
      --client-cert "$d/server.crt" --client-key "$d/server.key" >/dev/null 2>&1 && break; sleep 1
  done
  i=$((i+1))
done
export FABRIC_CFG_PATH=$B/peercfg CORE_PEER_TLS_ENABLED=true
setorg() {  # setorg <i>
  local i=$1; export CORE_PEER_LOCALMSPID=Org${i}MSP
  export CORE_PEER_TLS_ROOTCERT_FILE=$B/crypto/peerOrganizations/org$i.example.com/peers/peer0.org$i.example.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=$B/crypto/peerOrganizations/org$i.example.com/users/Admin@org$i.example.com/msp
  export CORE_PEER_ADDRESS=localhost:$((7051 + 2000*(i-1)))
}
for i in $(seq 1 "$N"); do
  setorg "$i"
  for t in $(seq 1 30); do peer channel join -b $CH.block >/dev/null 2>&1 && break; sleep 1; done
done
sleep 3
ORDARGS="-o localhost:7050 --ordererTLSHostnameOverride orderer0.example.com --tls --cafile $OCA"

# ---- chaincode lifecycle ----
( cd "$HERE/../chaincode" && GOFLAGS=-mod=mod go mod vendor )
peer lifecycle chaincode package $CC.tar.gz --path "$HERE/../chaincode" --lang golang --label ${CC}_1
PEERS=""
for i in $(seq 1 "$N"); do
  setorg "$i"; peer lifecycle chaincode install $CC.tar.gz >/dev/null 2>&1
  PEERS="$PEERS --peerAddresses localhost:$((7051 + 2000*(i-1))) --tlsRootCertFiles $CORE_PEER_TLS_ROOTCERT_FILE"
done
setorg 1
PKG=$(peer lifecycle chaincode queryinstalled --output json | python3 -c "import json,sys;print([c['package_id'] for c in json.load(sys.stdin)['installed_chaincodes'] if c['label']=='${CC}_1'][0])")
for i in $(seq 1 "$N"); do
  setorg "$i"
  peer lifecycle chaincode approveformyorg $ORDARGS --channelID $CH --name $CC --version 1 --package-id "$PKG" --sequence 1 >/dev/null 2>&1
done
setorg 1
peer lifecycle chaincode commit $ORDARGS --channelID $CH --name $CC --version 1 --sequence 1 $PEERS >/dev/null 2>&1
for t in $(seq 1 30); do
  peer lifecycle chaincode querycommitted --channelID $CH --name $CC >/dev/null 2>&1 && break; sleep 1
done
peer lifecycle chaincode querycommitted --channelID $CH --name $CC
echo "NETWORK_UP orgs=$N batch_timeout=$BT max_message_count=$MMC"
