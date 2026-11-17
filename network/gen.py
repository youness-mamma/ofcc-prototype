#!/usr/bin/env python3
"""Generate Fabric network config for N organizations (1 peer each) and 3 Raft orderers.

Usage: gen.py <n_orgs> <batch_timeout e.g. 1s> <max_message_count> <outdir>
Writes: crypto-config.yaml, configtx.yaml, compose.yaml into <outdir>.
Adapted from hyperledger/fabric-samples test-network (commit 5789681b), Apache-2.0.
"""
import sys, pathlib

n = int(sys.argv[1]); bt = sys.argv[2]; mmc = int(sys.argv[3]); out = pathlib.Path(sys.argv[4])
out.mkdir(parents=True, exist_ok=True)
ORD = [("orderer0", 7050, 7053, 9443), ("orderer1", 8050, 8053, 9444), ("orderer2", 9050, 9053, 9445)]
def peer_port(i): return 7051 + 2000 * (i - 1)          # 7051, 9051, 11051, ...
def ops_port(i): return 9500 + i

# ---------------- crypto-config.yaml ----------------
cc = ["OrdererOrgs:", "  - Name: Orderer", "    Domain: example.com", "    EnableNodeOUs: true", "    Specs:"]
for o, *_ in ORD:
    cc += [f"      - Hostname: {o}", "        SANS:", "          - localhost"]
cc += ["PeerOrgs:"]
for i in range(1, n + 1):
    cc += [f"  - Name: Org{i}", f"    Domain: org{i}.example.com", "    EnableNodeOUs: true",
           "    Template:", "      Count: 1", "      SANS:", "        - localhost",
           "    Users:", "      Count: 4"]          # User1 collector, User2 investigator, User3 auditor, User4 gateway client
(out / "crypto-config.yaml").write_text("\n".join(cc) + "\n")

# ---------------- configtx.yaml ----------------
def org_block(i):
    m = f"Org{i}MSP"
    return f"""  - &Org{i}
    Name: {m}
    ID: {m}
    MSPDir: crypto/peerOrganizations/org{i}.example.com/msp
    Policies:
      Readers: {{Type: Signature, Rule: "OR('{m}.admin', '{m}.peer', '{m}.client')"}}
      Writers: {{Type: Signature, Rule: "OR('{m}.admin', '{m}.client')"}}
      Admins: {{Type: Signature, Rule: "OR('{m}.admin')"}}
      Endorsement: {{Type: Signature, Rule: "OR('{m}.peer')"}}
    AnchorPeers:
      - Host: peer0.org{i}.example.com
        Port: {peer_port(i)}
"""
ct = f"""---
Organizations:
  - &OrdererOrg
    Name: OrdererOrg
    ID: OrdererMSP
    MSPDir: crypto/ordererOrganizations/example.com/msp
    Policies:
      Readers: {{Type: Signature, Rule: "OR('OrdererMSP.member')"}}
      Writers: {{Type: Signature, Rule: "OR('OrdererMSP.member')"}}
      Admins: {{Type: Signature, Rule: "OR('OrdererMSP.admin')"}}
    OrdererEndpoints:
""" + "".join(f"      - {o}.example.com:{p}\n" for o, p, *_ in ORD) + "".join(org_block(i) for i in range(1, n + 1)) + f"""
Capabilities:
  Channel: &ChannelCapabilities
    V2_0: true
  Orderer: &OrdererCapabilities
    V2_0: true
  Application: &ApplicationCapabilities
    V2_5: true
Application: &ApplicationDefaults
  Organizations:
  Policies:
    Readers: {{Type: ImplicitMeta, Rule: "ANY Readers"}}
    Writers: {{Type: ImplicitMeta, Rule: "ANY Writers"}}
    Admins: {{Type: ImplicitMeta, Rule: "MAJORITY Admins"}}
    LifecycleEndorsement: {{Type: ImplicitMeta, Rule: "MAJORITY Endorsement"}}
    Endorsement: {{Type: ImplicitMeta, Rule: "MAJORITY Endorsement"}}
  Capabilities:
    <<: *ApplicationCapabilities
Orderer: &OrdererDefaults
  BatchTimeout: {bt}
  BatchSize:
    MaxMessageCount: {mmc}
    AbsoluteMaxBytes: 99 MB
    PreferredMaxBytes: 2 MB
  Organizations:
  Policies:
    Readers: {{Type: ImplicitMeta, Rule: "ANY Readers"}}
    Writers: {{Type: ImplicitMeta, Rule: "ANY Writers"}}
    Admins: {{Type: ImplicitMeta, Rule: "MAJORITY Admins"}}
    BlockValidation: {{Type: ImplicitMeta, Rule: "ANY Writers"}}
Channel: &ChannelDefaults
  Policies:
    Readers: {{Type: ImplicitMeta, Rule: "ANY Readers"}}
    Writers: {{Type: ImplicitMeta, Rule: "ANY Writers"}}
    Admins: {{Type: ImplicitMeta, Rule: "MAJORITY Admins"}}
  Capabilities:
    <<: *ChannelCapabilities
Profiles:
  CustodyChannel:
    <<: *ChannelDefaults
    Orderer:
      <<: *OrdererDefaults
      OrdererType: etcdraft
      EtcdRaft:
        Consenters:
""" + "".join(f"""          - Host: {o}.example.com
            Port: {p}
            ClientTLSCert: crypto/ordererOrganizations/example.com/orderers/{o}.example.com/tls/server.crt
            ServerTLSCert: crypto/ordererOrganizations/example.com/orderers/{o}.example.com/tls/server.crt
""" for o, p, *_ in ORD) + """      Organizations:
        - *OrdererOrg
      Capabilities: *OrdererCapabilities
    Application:
      <<: *ApplicationDefaults
      Organizations:
""" + "".join(f"        - *Org{i}\n" for i in range(1, n + 1)) + """      Capabilities: *ApplicationCapabilities
"""
(out / "configtx.yaml").write_text(ct)

# ---------------- compose.yaml ----------------
vols, svcs = [], []
for o, p, ap, op in ORD:
    h = f"{o}.example.com"; vols.append(h)
    d = f"./crypto/ordererOrganizations/example.com/orderers/{h}"
    svcs.append(f"""  {h}:
    container_name: {h}
    image: hyperledger/fabric-orderer:${{FABRIC_VERSION}}
    environment:
      - FABRIC_LOGGING_SPEC=WARNING
      - ORDERER_GENERAL_LISTENADDRESS=0.0.0.0
      - ORDERER_GENERAL_LISTENPORT={p}
      - ORDERER_GENERAL_LOCALMSPID=OrdererMSP
      - ORDERER_GENERAL_LOCALMSPDIR=/var/hyperledger/orderer/msp
      - ORDERER_GENERAL_TLS_ENABLED=true
      - ORDERER_GENERAL_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_GENERAL_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_GENERAL_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_GENERAL_CLUSTER_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_GENERAL_BOOTSTRAPMETHOD=none
      - ORDERER_CHANNELPARTICIPATION_ENABLED=true
      - ORDERER_ADMIN_TLS_ENABLED=true
      - ORDERER_ADMIN_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_ADMIN_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_ADMIN_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_ADMIN_TLS_CLIENTROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_ADMIN_LISTENADDRESS=0.0.0.0:{ap}
      - ORDERER_OPERATIONS_LISTENADDRESS={h}:{op}
    working_dir: /root
    command: orderer
    volumes:
      - {d}/msp:/var/hyperledger/orderer/msp
      - {d}/tls/:/var/hyperledger/orderer/tls
      - {h}:/var/hyperledger/production/orderer
    ports:
      - {p}:{p}
      - {ap}:{ap}
    networks: [custody]
""")
for i in range(1, n + 1):
    h = f"peer0.org{i}.example.com"; vols.append(h); pp = peer_port(i)
    svcs.append(f"""  {h}:
    container_name: {h}
    image: hyperledger/fabric-peer:${{FABRIC_VERSION}}
    environment:
      - FABRIC_CFG_PATH=/etc/hyperledger/peercfg
      - FABRIC_LOGGING_SPEC=WARNING
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_PROFILE_ENABLED=false
      - CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tls/server.crt
      - CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tls/server.key
      - CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt
      - CORE_PEER_ID={h}
      - CORE_PEER_ADDRESS={h}:{pp}
      - CORE_PEER_LISTENADDRESS=0.0.0.0:{pp}
      - CORE_PEER_CHAINCODEADDRESS={h}:{pp + 1}
      - CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:{pp + 1}
      - CORE_PEER_GOSSIP_BOOTSTRAP={h}:{pp}
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT={h}:{pp}
      - CORE_PEER_LOCALMSPID=Org{i}MSP
      - CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp
      - CORE_OPERATIONS_LISTENADDRESS={h}:{ops_port(i)}
      - CORE_CHAINCODE_EXECUTETIMEOUT=300s
      - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
      - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=custody_net
    volumes:
      - ./crypto/peerOrganizations/org{i}.example.com/peers/{h}:/etc/hyperledger/fabric
      - ./peercfg:/etc/hyperledger/peercfg
      - {h}:/var/hyperledger/production
      - /var/run/docker.sock:/host/var/run/docker.sock
    working_dir: /root
    command: peer node start
    ports:
      - {pp}:{pp}
    networks: [custody]
""")
comp = "volumes:\n" + "".join(f"  {v}:\n" for v in vols) + "networks:\n  custody:\n    name: custody_net\nservices:\n" + "".join(svcs)
(out / "compose.yaml").write_text(comp)
print(f"generated network for {n} orgs, BatchTimeout={bt}, MaxMessageCount={mmc} in {out}")
