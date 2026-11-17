// Package tamper applies simulated tampering operations to synthetic records inside the testbed.
// Defensive evaluation only: every operation is logged as ground truth so detection rates are exact.
package tamper

import (
	"math/rand"
	"sort"

	"ofcc/chaincode/model"
	"ofcc/client/internal/sim"
)

// Ops lists the seven operation types.
var Ops = []string{"modEntry", "modPayload", "delete", "truncate", "insert", "reorder", "replay"}

// Op is the ground-truth record of one injected operation.
type Op struct {
	Type     string  `json:"type"`
	Pos      string  `json:"pos"` // "pre" (gateway store / in transit) or "post" (store or server after upload)
	GW       int     `json:"gw"`
	Round    int     `json:"round"`
	Targets  []int64 `json:"targets"` // ground-truth capture indices affected
	Key      string  `json:"key,omitempty"` // object inserted after upload (orphan)
	Refs     []Ref   `json:"refs,omitempty"` // cross-gateway targets by digest (CL truncate)
	Detected bool    `json:"detected"`
	DetectedItem bool `json:"detected_item"` // stricter: an alert names an affected item
	NA       bool    `json:"na,omitempty"` // operation not applicable to this system at this position
}

// Ref names an item by gateway and captured digest.
type Ref struct {
	GW int    `json:"gw"`
	D  string `json:"d"`
}

// Repairer knows how a system's unkeyed fields can be recomputed by an adaptive adversary.
type Repairer struct {
	Signed     bool   // entries carry signatures (repair impossible)
	Chain      bool   // entries carry prev hashes
	Seq        bool   // entries carry sequence numbers
	Pg         string // gateway pseudonym (public)
	AnchorSeq  int64  // last anchored sequence number (public on the ledger)
	AnchorHash string // last anchored hash (public on the ledger)
	AnchorT    int64  // last anchored capture time (public on the ledger)
}

// Repair renumbers and re-chains records when nothing is signed, so that the batch is self-consistent.
func (rp Repairer) Repair(recs []*sim.Record) {
	if rp.Signed {
		return
	}
	// timestamps are unkeyed too: reassign them in increasing order of position
	ts := make([]int64, len(recs))
	for i, r := range recs {
		ts[i] = r.T
	}
	sort.Slice(ts, func(a, b int) bool { return ts[a] < ts[b] })
	for i := range ts { // keep times strictly after the last anchored one and strictly increasing
		lo := rp.AnchorT
		if i > 0 {
			lo = ts[i-1]
		}
		if ts[i] <= lo {
			ts[i] = lo + 1
		}
	}
	prev := rp.AnchorHash
	for i, r := range recs {
		r.T = ts[i]
		if rp.Seq {
			r.Seq = rp.AnchorSeq + int64(i) + 1
		}
		r.D = model.H(r.Cipher)
		if rp.Chain {
			r.Prev = prev
			prev = model.EntryHash(rp.Pg, r.Entry())
		}
	}
}

func flip(b []byte, rng *rand.Rand) []byte {
	c := append([]byte(nil), b...)
	if len(c) > 0 {
		i := rng.Intn(len(c))
		c[i] ^= 0x5a
	}
	return c
}

// ApplyPre applies op to the pending records of one gateway before upload.
// history holds already-uploaded records of the same gateway (source for replay).
func ApplyPre(op *Op, recs []*sim.Record, history []*sim.Record, adaptive bool, rp Repairer, rng *rand.Rand) []*sim.Record {
	n := len(recs)
	if n < 4 {
		op.NA = true
		return recs
	}
	i := 1 + rng.Intn(n-3) // interior position, leaves room after it
	switch op.Type {
	case "modEntry":
		recs[i].T += 1_000_000_000
		op.Targets = []int64{recs[i].Orig}
	case "modPayload":
		recs[i].Cipher = flip(recs[i].Cipher, rng)
		op.Targets = []int64{recs[i].Orig}
	case "delete":
		op.Targets = []int64{recs[i].Orig}
		recs = append(recs[:i:i], recs[i+1:]...)
	case "truncate":
		m := 3
		for _, r := range recs[n-m:] {
			op.Targets = append(op.Targets, r.Orig)
		}
		recs = recs[:n-m]
	case "insert":
		f := *recs[i]
		f.Forged, f.Orig = true, -1
		f.Cipher = flip(f.Cipher, rng)
		f.D = model.H(f.Cipher)
		f.Sig = model.Sign(randomKey(rng), []byte("forged")) // attacker cannot sign as the gateway
		op.Targets = []int64{recs[i].Orig}
		recs = append(recs[:i:i], append([]*sim.Record{&f}, recs[i:]...)...)
	case "reorder":
		op.Targets = []int64{recs[i].Orig, recs[i+1].Orig}
		recs[i], recs[i+1] = recs[i+1], recs[i]
	case "replay":
		if len(history) == 0 {
			op.NA = true
			return recs
		}
		old := *history[rng.Intn(len(history))]
		op.Targets = []int64{old.Orig}
		recs = append(recs[:i:i], append([]*sim.Record{&old}, recs[i:]...)...)
	}
	if adaptive {
		rp.Repair(recs)
	}
	return recs
}

func randomKey(rng *rand.Rand) []byte {
	k := make([]byte, 64)
	rng.Read(k)
	seed := k[:32]
	return ed25519FromSeed(seed)
}

// SortedTargets returns targets sorted (for stable JSON).
func (o *Op) SortedTargets() []int64 {
	t := append([]int64(nil), o.Targets...)
	sort.Slice(t, func(a, b int) bool { return t[a] < t[b] })
	return t
}
