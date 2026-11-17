// Package fab connects to the custody chaincode through the Fabric Gateway (pattern of the
// official fabric-samples application-gateway-go sample).
package fab

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Conn is a gateway connection for one identity.
type Conn struct {
	gw       *client.Gateway
	grpcConn *grpc.ClientConn
	Contract *client.Contract
	Name     string
}

func firstFile(dir string) ([]byte, error) {
	m, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil || len(m) == 0 {
		return nil, fmt.Errorf("no file in %s", dir)
	}
	return os.ReadFile(m[0])
}

// Connect opens a connection as user (e.g. "Admin", "User1") of org userOrg, through the org1 peer gateway.
func Connect(cryptoDir string, userOrg int, user string) (*Conn, error) {
	org := fmt.Sprintf("org%d.example.com", userOrg)
	udir := filepath.Join(cryptoDir, "peerOrganizations", org, "users", fmt.Sprintf("%s@%s", user, org), "msp")
	certPEM, err := firstFile(filepath.Join(udir, "signcerts"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := firstFile(filepath.Join(udir, "keystore"))
	if err != nil {
		return nil, err
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, err
	}
	id, err := identity.NewX509Identity(fmt.Sprintf("Org%dMSP", userOrg), cert)
	if err != nil {
		return nil, err
	}
	pk, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	sign, err := identity.NewPrivateKeySign(pk)
	if err != nil {
		return nil, err
	}
	tlsPEM, err := os.ReadFile(filepath.Join(cryptoDir, "peerOrganizations", "org1.example.com", "peers",
		"peer0.org1.example.com", "tls", "ca.crt"))
	if err != nil {
		return nil, err
	}
	tlsCert, err := identity.CertificateFromPEM(tlsPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(tlsCert)
	gc, err := grpc.NewClient("dns:///localhost:7051",
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, "peer0.org1.example.com")),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(256<<20)))
	if err != nil {
		return nil, err
	}
	gw, err := client.Connect(id, client.WithSign(sign), client.WithHash(hash.SHA256), client.WithClientConnection(gc),
		client.WithEvaluateTimeout(60*time.Second), client.WithEndorseTimeout(60*time.Second),
		client.WithSubmitTimeout(30*time.Second), client.WithCommitStatusTimeout(5*time.Minute))
	if err != nil {
		return nil, err
	}
	return &Conn{gw: gw, grpcConn: gc, Contract: gw.GetNetwork("custody").GetContract("custody"),
		Name: fmt.Sprintf("%s@%s", user, org)}, nil
}

// Close closes the connection.
func (c *Conn) Close() { c.gw.Close(); c.grpcConn.Close() }

// Submit submits a transaction and waits for commit; returns result, transaction ID and latency.
func (c *Conn) Submit(fn string, args ...string) ([]byte, string, time.Duration, error) {
	t0 := time.Now()
	res, commit, err := c.Contract.SubmitAsync(fn, client.WithArguments(args...))
	if err != nil {
		return nil, "", 0, err
	}
	st, err := commit.Status()
	if err != nil {
		return nil, commit.TransactionID(), 0, err
	}
	if !st.Successful {
		return nil, st.TransactionID, 0, fmt.Errorf("tx %s failed with code %d", st.TransactionID, int32(st.Code))
	}
	return res, st.TransactionID, time.Since(t0), nil
}

// Evaluate runs a query.
func (c *Conn) Evaluate(fn string, args ...string) ([]byte, error) {
	return c.Contract.EvaluateTransaction(fn, args...)
}
