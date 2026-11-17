package systems

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"ofcc/chaincode/model"
	"ofcc/client/internal/fab"
	"ofcc/client/internal/sim"
	"ofcc/client/internal/store"
	"ofcc/client/internal/tamper"
)

const collector = "User1@org1.example.com"
const investigator = "User2@org1.example.com"
const investigator2 = "User2@org2.example.com"

// Ledger implements OFCC (mode ofcc and its ablations) and the hash archive (mode ha).
type Ledger struct {
	Mode  model.Mode
	C     *Conns
	St    *store.Store
	mu    sync.Mutex
	txGW  map[string][2]int // tx -> (gw, round)
	heads map[int][2]string // gw -> (anchored seq as string, anchored hash), public on the ledger
	anch  map[int]int64
}

func NewLedger(mode model.Mode, c *Conns, st *store.Store) *Ledger {
	return &Ledger{Mode: mode, C: c, St: st, txGW: map[string][2]int{}, heads: map[int][2]string{}, anch: map[int]int64{}}
}

func (l *Ledger) Name() string { return l.Mode.Name }

func (l *Ledger) Register(g *sim.Gateway) error {
	_, _, _, err := l.C.Admin.Submit("RegisterGateway", g.PubB64(), l.Mode.Name, collector)
	return err
}

// Repairer reflects what an adaptive adversary can recompute: everything unkeyed, nothing signed.
func (l *Ledger) Repairer(g *sim.Gateway) tamper.Repairer {
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.heads[g.Idx][1]
	if h == "" {
		h = model.Genesis(g.Pg)
	}
	if l.Mode.Name == "ha" {
		return tamper.Repairer{Signed: false, Chain: false, Seq: true, Pg: g.Pg, AnchorSeq: l.anch[g.Idx], AnchorHash: h}
	}
	return tamper.Repairer{Signed: l.Mode.Sig, Chain: l.Mode.Chain, Seq: l.Mode.Seq, Pg: g.Pg, AnchorSeq: l.anch[g.Idx], AnchorHash: h}
}

func (l *Ledger) key(g *sim.Gateway, r *sim.Record) string {
	if l.Mode.Name == "ha" {
		return g.Pg + "/" + seqID(r.Seq)
	}
	return g.Pg + "/" + r.D
}

func (l *Ledger) Sync(g *sim.Gateway, recs []*sim.Record, round int, b int) (SyncOut, error) {
	var out SyncOut
	keys := make([]string, len(recs))
	vals := make([][]byte, len(recs))
	for i, r := range recs {
		keys[i], vals[i] = l.key(g, r), r.Cipher
		out.LinkBytes += int64(len(r.Cipher))
	}
	if err := parallelPut(l.St, keys, vals); err != nil {
		return out, err
	}
	var parts []string
	if l.Mode.Name == "ha" {
		items := make([]model.DigestItem, len(recs))
		for i, r := range recs {
			items[i] = model.DigestItem{ID: seqID(r.Seq), D: r.D}
		}
		for _, ch := range chunks(items, b) {
			bb, _ := json.Marshal(model.DigestBatch{Pg: g.Pg, Items: ch})
			parts = append(parts, string(bb))
		}
	} else {
		entries := make([]model.Entry, len(recs))
		for i, r := range recs {
			entries[i] = r.Entry()
		}
		cs := chunks(entries, b)
		for i, ch := range cs {
			bt := model.Batch{Pg: g.Pg, Entries: ch}
			if i == len(cs)-1 {
				if l.Mode.Prot {
					bt.Header = g.Header() // from the protected state, not from the store
				} else if len(recs) > 0 {
					bt.Header = g.HeaderFromStore(recs[len(recs)-1])
				}
			}
			bb, _ := json.Marshal(bt)
			parts = append(parts, string(bb))
		}
	}
	fn := "AnchorBatch"
	if l.Mode.Name == "ha" {
		fn = "AnchorDigests"
	}
	for _, p := range parts {
		out.LinkBytes += int64(len(p))
		res, tx, lat, err := l.C.Gateway.Submit(fn, p)
		if err != nil {
			return out, fmt.Errorf("%s: %w", fn, err)
		}
		out.Txs++
		out.Lat = append(out.Lat, lat.Seconds())
		l.mu.Lock()
		l.txGW[tx] = [2]int{g.Idx, round}
		l.mu.Unlock()
		var evs []model.Event
		_ = json.Unmarshal(res, &evs)
		for _, e := range evs {
			out.Alerts = append(out.Alerts, Alert{GW: g.Idx, Round: round, Orig: -1, Kind: e.Type, Seq: e.Seq, From: e.From, To: e.To})
		}
	}
	// track the public anchored head (needed by an adaptive adversary)
	gb, err := l.C.Gateway.Evaluate("GetGateway", g.Pg)
	if err == nil {
		var st struct {
			A  int64  `json:"a"`
			Ha string `json:"ha"`
		}
		if json.Unmarshal(gb, &st) == nil {
			l.mu.Lock()
			l.anch[g.Idx], l.heads[g.Idx] = st.A, [2]string{fmt.Sprint(st.A), st.Ha}
			l.mu.Unlock()
		}
	}
	if l.Mode.Name == "ha" || !l.Mode.Seq { // HA ids and noSeq have no ledger head counter
		l.mu.Lock()
		mx := l.anch[g.Idx]
		for _, r := range recs {
			if r.Seq > mx {
				mx = r.Seq
			}
		}
		l.anch[g.Idx] = mx
		l.mu.Unlock()
	}
	return out, nil
}

// Post tampers with the off-chain store after upload (an insider of one organization).
// Ledger records cannot be changed by a single organization (A4), so entry-level operations are N/A.
func (l *Ledger) Post(op *tamper.Op, g *sim.Gateway, target, other *sim.Record, adaptive bool, rng *rand.Rand) error {
	k := l.key(g, target)
	op.Targets = []int64{target.Orig}
	switch op.Type {
	case "modPayload":
		b, err := l.St.Get(k)
		if err != nil || b == nil {
			return fmt.Errorf("post: object %s: %v", k, err)
		}
		return l.St.Put(k, flip(b, rng))
	case "delete":
		return l.St.Remove(k)
	case "insert":
		fk := fmt.Sprintf("%s/forged-%d-%d", g.Pg, target.Orig, rng.Int63())
		op.Targets = nil
		op.Key = fk
		return l.St.Put(fk, flip(target.Cipher, rng))
	case "replay": // copy another item's object over the target's key
		b, err := l.St.Get(l.key(g, other))
		if err != nil || b == nil {
			return fmt.Errorf("post replay: %v", err)
		}
		return l.St.Put(k, b)
	default: // modEntry, truncate, reorder act on ledger entries
		op.NA = true
		return nil
	}
}

func (l *Ledger) itemID(g *sim.Gateway, r *sim.Record) string {
	if l.Mode.Name == "ha" || l.Mode.Seq {
		return seqID(r.Seq)
	}
	return model.EntryHash(g.Pg, r.Entry())
}

// Transfer performs collector -> investigator -> second investigator. Each step is retried on its own;
// a retry that finds the step already applied ("not the current custodian" after an earlier attempt) is accepted.
func (l *Ledger) Transfer(g *sim.Gateway, r *sim.Record) error {
	id := l.itemID(g, r)
	step := func(c *fab.Conn, to string) error {
		var err error
		for try := 0; try < 3; try++ {
			_, _, _, err = c.Submit("TransferCustody", g.Pg, id, to)
			if err == nil {
				return nil
			}
			if try > 0 && strings.Contains(err.Error(), "not the current custodian") {
				return nil // the earlier attempt committed after all
			}
			time.Sleep(time.Second)
		}
		return err
	}
	if err := step(l.C.Collector, investigator); err != nil {
		return err
	}
	return step(l.C.Investigator, investigator2)
}

func (l *Ledger) Verify(gws []*sim.Gateway, t *Truth) (VerifyOut, error) {
	out := VerifyOut{Complete: map[int]map[int64]bool{}, CustodyBroken: map[int]map[int64]bool{}}
	for _, g := range gws {
		items, evs, err := getLedger(l.C.Auditor, g.Pg)
		if err != nil {
			return out, err
		}
		badSeq := map[int64]bool{} // sequence numbers in a gap or conflict
		for _, e := range evs {
			switch e.Type {
			case "gap":
				for s := e.From; s <= e.To; s++ {
					badSeq[s] = true
				}
			case "conflict":
				badSeq[e.Seq] = true
			}
		}
		onLedger := map[string]bool{}
		okOrig := map[int64]bool{}
		for _, it := range items {
			k := g.Pg + "/" + it.D
			if l.Mode.Name == "ha" {
				k = g.Pg + "/" + seqID(it.Seq)
			}
			onLedger[k] = true
			o, rd := t.orig(g.Idx, it.D)
			if rd < 0 {
				if v, ok := l.txGW[it.Tx]; ok {
					rd = v[1]
				}
			}
			obj, err := l.St.Get(k)
			if err != nil {
				return out, err
			}
			bad := false
			if obj == nil {
				out.Alerts = append(out.Alerts, Alert{GW: g.Idx, Round: rd, Orig: o, Kind: "missing"})
				bad = true
			} else if model.H(obj) != it.D {
				out.Alerts = append(out.Alerts, Alert{GW: g.Idx, Round: rd, Orig: o, Kind: "v5"})
				bad = true
			}
			if l.Mode.Seq && badSeq[it.Seq] && l.Mode.Name != "ha" {
				bad = true
			}
			if !custodyOK(it, collector) {
				bad = true
				if o >= 0 {
					if out.CustodyBroken[g.Idx] == nil {
						out.CustodyBroken[g.Idx] = map[int64]bool{}
					}
					out.CustodyBroken[g.Idx][o] = true
				}
			}
			if it.TimeFlag {
				bad = true
			}
			if o >= 0 && !bad {
				okOrig[o] = true
			}
		}
		if l.Mode.Name == "ha" { // contiguity check over item ids
			var mx int64
			have := map[int64]bool{}
			for _, it := range items {
				have[it.Seq] = true
				if it.Seq > mx {
					mx = it.Seq
				}
			}
			for s := int64(1); s <= mx; s++ {
				if !have[s] {
					out.Alerts = append(out.Alerts, Alert{GW: g.Idx, Round: t.roundOf(g.Idx, s), Orig: s, Kind: "idgap"})
				}
			}
		}
		keys, err := l.St.List(g.Pg + "/")
		if err != nil {
			return out, err
		}
		for _, k := range keys {
			if !onLedger[k] {
				out.Alerts = append(out.Alerts, Alert{GW: g.Idx, Round: -1, Orig: -1, Key: k, Kind: "orphan"})
			}
		}
		out.Complete[g.Idx] = okOrig
	}
	sortAlerts(out.Alerts)
	return out, nil
}

// OffchainBytes returns the bytes held in this run's bucket.
func (l *Ledger) OffchainBytes() int64 { n, _ := l.St.Size(); return n }

// CustodyAttack: "forge" = an identity that is not the current custodian submits a transfer;
// the chaincode must reject it. "rewrite" = change committed custody history, which a single
// organization cannot do without a majority of endorsers (A4): prevented by construction.
func (l *Ledger) CustodyAttack(kind string, g *sim.Gateway, r *sim.Record, adaptive bool) (string, error) {
	switch kind {
	case "forge":
		_, _, _, err := l.C.Investigator2.Submit("TransferCustody", g.Pg, l.itemID(g, r), investigator2)
		if err != nil {
			if strings.Contains(err.Error(), "not the current custodian") {
				return "prevented", nil
			}
			return "", err
		}
		return "accepted", nil
	case "rewrite":
		return "prevented", nil
	}
	return "", fmt.Errorf("unknown custody attack %s", kind)
}
