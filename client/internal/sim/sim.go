// Package sim simulates evidence gateways: synthetic payloads, encryption, signing,
// hash chaining and the protected state (paper Sec. 4.1). Capture runs on a virtual clock
// so that long outages can be simulated quickly; all ledger interaction happens in real time.
package sim

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"

	"ofcc/chaincode/model"
)

// Record is one evidence item as held in the gateway's local store.
type Record struct {
	GW     int    // gateway index
	Orig   int64  // ground-truth capture index (never changed by tampering)
	Seq    int64  // sequence number as stored (may be renumbered by an adaptive adversary)
	T      int64  // capture time, unix ns
	Cipher []byte // payload as stored/uploaded (ciphertext, or plaintext when Enc is off)
	D      string // digest as stored
	Prev   string
	Sig    string
	Forged bool // ground truth: inserted by the tamper tool
	Kind   string
}

// Entry converts the record to the wire entry.
func (r *Record) Entry() model.Entry {
	return model.Entry{Seq: r.Seq, T: r.T, D: r.D, Prev: r.Prev, Sig: r.Sig}
}

// Gateway is one simulated evidence gateway.
type Gateway struct {
	Idx   int
	Priv  ed25519.PrivateKey
	Pub   ed25519.PublicKey
	Pg    string
	Mode  model.Mode
	key   []byte
	aead  cipher.AEAD
	rng   *rand.Rand
	count int64 // ground-truth capture counter
	// protected state (A2): last sequence number and last chain hash; the tamper tool cannot write these.
	K  int64
	Hk string
}

// New creates gateway idx. The workload (payload contents) depends only on (seed, idx), so all
// compared systems see identical items; keys also depend on salt, so each run registers fresh gateways.
func New(idx int, mode model.Mode, seed int64, salt int64) *Gateway {
	rng := rand.New(rand.NewSource(seed*1000003 + int64(idx)))
	krng := rand.New(rand.NewSource(seed*7919 + int64(idx)*104729 + salt*15485863))
	kseed := make([]byte, ed25519.SeedSize)
	krng.Read(kseed)
	priv := ed25519.NewKeyFromSeed(kseed)
	pub := priv.Public().(ed25519.PublicKey)
	key := make([]byte, 32)
	krng.Read(key)
	blk, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(blk)
	pg := model.Pseudonym(pub)
	return &Gateway{Idx: idx, Priv: priv, Pub: pub, Pg: pg, Mode: mode, key: key, aead: aead, rng: rng, Hk: model.Genesis(pg)}
}

// PubB64 returns the public key for registration.
func (g *Gateway) PubB64() string { return base64.StdEncoding.EncodeToString(g.Pub) }

// payload builds a synthetic evidence item: alternately a sensor batch (~1 KB) or an alert log (2-50 KB).
func (g *Gateway) payload(n int64, t int64) ([]byte, string) {
	if n%2 == 0 {
		vals := make([]float64, 60)
		for i := range vals {
			vals[i] = float64(g.rng.Intn(100000)) / 100
		}
		b, _ := json.Marshal(map[string]any{"gw": g.Idx, "n": n, "t": t, "type": "sensor_batch",
			"fields": []string{"lat", "lon", "sog", "cog", "rpm", "temp"}, "values": vals})
		return b, "sensor"
	}
	size := 2048 + g.rng.Intn(48*1024)
	lines := make([]byte, 0, size)
	for len(lines) < size {
		lines = append(lines, fmt.Sprintf("%d ids alert sig=%d src=10.0.%d.%d dst=10.1.%d.%d sev=%d\n",
			t, g.rng.Intn(9000)+1000, g.rng.Intn(255), g.rng.Intn(255), g.rng.Intn(255), g.rng.Intn(255), g.rng.Intn(5))...)
	}
	return lines[:size], "alert"
}

// Encrypt encrypts a payload with the gateway's content key (AES-256-GCM, random nonce prepended).
func (g *Gateway) Encrypt(p []byte) []byte {
	nonce := make([]byte, g.aead.NonceSize())
	g.rng.Read(nonce)
	return append(nonce, g.aead.Seal(nil, nonce, p, nil)...)
}

// Capture creates the next evidence item at virtual time t and updates the protected state.
func (g *Gateway) Capture(t int64) *Record {
	g.count++
	p, kind := g.payload(g.count, t)
	c := p
	if g.Mode.Enc {
		c = g.Encrypt(p)
	}
	r := &Record{GW: g.Idx, Orig: g.count, T: t, Cipher: c, D: model.H(c), Kind: kind}
	if g.Mode.Name == "ha" || g.Mode.Name == "cl" {
		r.Seq = g.count // unsigned local counter
		return r
	}
	if g.Mode.Seq {
		r.Seq = g.count
	}
	if g.Mode.Chain {
		r.Prev = g.Hk
	}
	e := r.Entry()
	h := model.EntryHash(g.Pg, e)
	if g.Mode.Sig {
		r.Sig = model.Sign(g.Priv, []byte(h))
	}
	g.K, g.Hk = g.count, h
	return r
}

// Header returns the signed header eta from the protected state (nil when the mode has no header).
func (g *Gateway) Header() *model.Header {
	if !(g.Mode.Sig && g.Mode.Seq) {
		return nil
	}
	return &model.Header{K: g.K, Hk: g.Hk, Sig: model.Sign(g.Priv, model.HeaderBytes(g.Pg, g.K, g.Hk))}
}

// Rng exposes the gateway's deterministic random source.
func (g *Gateway) Rng() *rand.Rand { return g.rng }
