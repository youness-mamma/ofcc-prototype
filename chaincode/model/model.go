// Package model holds the wire format shared by the custody chaincode and the client,
// so that both compute exactly the same bytes for hashing and signing (paper Eq. (1)).
package model

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Mode selects OFCC or one of its ablations, or the hash-archive baseline.
type Mode struct {
	Name  string `json:"name"`  // ofcc | noChain | noSig | noSeq | noEnc | ha
	Chain bool   `json:"chain"` // entries carry h_{j-1}
	Sig   bool   `json:"sig"`   // entries and headers are Ed25519-signed
	Seq   bool   `json:"seq"`   // entries carry sequence numbers and the signed header carries k
	Enc   bool   `json:"enc"`   // payloads are encrypted before upload (affects cost only)
}

// ModeByName returns the mechanism flags of each configuration.
func ModeByName(n string) (Mode, error) {
	m := Mode{Name: n, Chain: true, Sig: true, Seq: true, Enc: true}
	switch n {
	case "ofcc":
	case "noChain":
		m.Chain = false
	case "noSig":
		m.Sig = false
	case "noSeq":
		m.Seq = false
	case "noEnc":
		m.Enc = false
	case "ha":
		m = Mode{Name: "ha", Enc: true}
	default:
		return m, fmt.Errorf("unknown mode %q", n)
	}
	return m, nil
}

// Entry is e_j = (p_g, j, t_j, d_j, h_{j-1}) plus its signature.
type Entry struct {
	Seq  int64  `json:"seq"`
	T    int64  `json:"t"`    // capture time, unix nanoseconds (gateway clock)
	D    string `json:"d"`    // hex SHA-256 of the (encrypted) payload
	Prev string `json:"prev"` // hex h_{j-1}, empty when chaining is off
	Sig  string `json:"sig"`  // base64 Ed25519 signature over h_j, empty when signatures are off
}

// Header is eta = (p_g, k, h_k, Sign(p_g || k || h_k)).
type Header struct {
	K   int64  `json:"k"`
	Hk  string `json:"hk"`
	Sig string `json:"sig"`
}

// Batch is what a gateway submits on reconnection.
type Batch struct {
	Pg      string  `json:"pg"`
	Header  *Header `json:"header,omitempty"`
	Entries []Entry `json:"entries"`
}

// DigestItem / DigestBatch are used by the hash-archive (HA) baseline.
type DigestItem struct {
	ID string `json:"id"`
	D  string `json:"d"`
}
type DigestBatch struct {
	Pg    string       `json:"pg"`
	Items []DigestItem `json:"items"`
}

// Event is something the chaincode reports: gap, duplicate, conflict, reorder, reject, timeflag, linkbreak, headerreject.
type Event struct {
	Type string `json:"type"`
	Pg   string `json:"pg"`
	From int64  `json:"from,omitempty"`
	To   int64  `json:"to,omitempty"`
	Seq  int64  `json:"seq,omitempty"`
	H    string `json:"h,omitempty"`
	ID   string `json:"id,omitempty"`
	Tx   string `json:"tx"`
}

// H is SHA-256 in hex.
func H(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// EntryBytes is the canonical encoding hashed into h_j.
func EntryBytes(pg string, e Entry) []byte {
	return []byte(fmt.Sprintf("OFCC1|%s|%d|%d|%s|%s", pg, e.Seq, e.T, e.D, e.Prev))
}

// EntryHash returns h_j.
func EntryHash(pg string, e Entry) string { return H(EntryBytes(pg, e)) }

// HeaderBytes is the canonical encoding signed in the header.
func HeaderBytes(pg string, k int64, hk string) []byte {
	return []byte(fmt.Sprintf("OFCC1H|%s|%d|%s", pg, k, hk))
}

// Genesis returns h_0 = H(p_g).
func Genesis(pg string) string { return H([]byte(pg)) }

// Pseudonym returns p_g = H(pk_g).
func Pseudonym(pub ed25519.PublicKey) string { return H(pub) }

// Verify checks an Ed25519 signature given as base64 over msg.
func Verify(pub ed25519.PublicKey, msg []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// Sign signs msg and returns base64.
func Sign(priv ed25519.PrivateKey, msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
}
