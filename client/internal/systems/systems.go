// Package systems implements the compared systems behind one interface:
// OFCC and its ablations (ledger + off-chain store), the hash archive HA (per-item digests on the
// ledger + store), and the centralized log CL (one ingest server with a server-side hash chain).
package systems

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"sync"

	"ofcc/chaincode/model"
	"ofcc/client/internal/fab"
	"ofcc/client/internal/sim"
	"ofcc/client/internal/store"
	"ofcc/client/internal/tamper"
)

// Alert is anything a system reports that may indicate tampering.
type Alert struct {
	GW    int    `json:"gw"`
	Round int    `json:"round"` // -1 if unknown
	Orig  int64  `json:"orig"`  // -1 if unknown
	Key   string `json:"key,omitempty"`
	Kind  string `json:"kind"`
}

// SyncOut is the result of one synchronization.
type SyncOut struct {
	Alerts    []Alert
	LinkBytes int64
	Txs       int
	Lat       []float64 // per-transaction submit-to-commit latency, seconds
}

// Truth is the ground truth the verifier uses only to attribute alerts to items and rounds.
type Truth struct {
	mu        sync.Mutex
	DigestOf  map[int]map[int64]string // gw -> orig -> captured digest
	OrigOf    map[int]map[string]int64 // gw -> captured digest -> orig
	RoundOf   map[int]map[int64]int    // gw -> orig -> round
}

func NewTruth() *Truth {
	return &Truth{DigestOf: map[int]map[int64]string{}, OrigOf: map[int]map[string]int64{}, RoundOf: map[int]map[int64]int{}}
}

func (t *Truth) Add(r *sim.Record, round int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.DigestOf[r.GW] == nil {
		t.DigestOf[r.GW], t.OrigOf[r.GW], t.RoundOf[r.GW] = map[int64]string{}, map[string]int64{}, map[int64]int{}
	}
	t.DigestOf[r.GW][r.Orig], t.OrigOf[r.GW][r.D], t.RoundOf[r.GW][r.Orig] = r.D, r.Orig, round
}

func (t *Truth) orig(gw int, d string) (int64, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if o, ok := t.OrigOf[gw][d]; ok {
		return o, t.RoundOf[gw][o]
	}
	return -1, -1
}

func (t *Truth) roundOf(gw int, o int64) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r, ok := t.RoundOf[gw][o]; ok {
		return r
	}
	return -1
}

// VerifyOut is the verifier's output.
type VerifyOut struct {
	Alerts   []Alert
	Complete map[int]map[int64]bool // gw -> orig -> custody complete
}

// System is implemented by OFCC (all modes), HA and CL.
type System interface {
	Name() string
	Register(g *sim.Gateway) error
	Repairer(g *sim.Gateway) tamper.Repairer
	Sync(g *sim.Gateway, recs []*sim.Record, round int, b int) (SyncOut, error)
	Post(op *tamper.Op, g *sim.Gateway, target, other *sim.Record, adaptive bool, rng *rand.Rand) error
	Transfer(g *sim.Gateway, r *sim.Record) error
	Verify(gws []*sim.Gateway, t *Truth) (VerifyOut, error)
}

// Conns bundles the Fabric identities used by the ledger-based systems.
type Conns struct {
	Admin, Gateway, Collector, Investigator, Investigator2, Auditor *fab.Conn
}

func chunks[T any](xs []T, b int) [][]T {
	var out [][]T
	for len(xs) > b {
		out = append(out, xs[:b])
		xs = xs[b:]
	}
	if len(xs) > 0 || len(out) == 0 {
		out = append(out, xs)
	}
	return out
}

func parallelPut(st *store.Store, keys []string, vals [][]byte) error {
	var wg sync.WaitGroup
	errs := make(chan error, len(keys))
	sem := make(chan struct{}, 8)
	for i := range keys {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := st.Put(keys[i], vals[i]); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	return <-errs
}

func flip(b []byte, rng *rand.Rand) []byte {
	c := append([]byte(nil), b...)
	if len(c) > 0 {
		c[rng.Intn(len(c))] ^= 0x5a
	}
	return c
}

func seqID(s int64) string { return fmt.Sprintf("%016d", s) }

// ledgerItem mirrors the chaincode Item.
type ledgerItem struct {
	Seq       int64  `json:"seq"`
	H         string `json:"h"`
	D         string `json:"d"`
	T         int64  `json:"t"`
	TimeFlag  bool   `json:"tf"`
	Tx        string `json:"tx"`
	Custodian string `json:"cust"`
	Transfers []struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"xfer"`
}

func getLedger(c *fab.Conn, pg string) ([]ledgerItem, []model.Event, error) {
	ib, err := c.Evaluate("GetItems", pg)
	if err != nil {
		return nil, nil, err
	}
	var items []ledgerItem
	if err := json.Unmarshal(ib, &items); err != nil {
		return nil, nil, err
	}
	eb, err := c.Evaluate("GetEvents", pg)
	if err != nil {
		return nil, nil, err
	}
	var groups [][]model.Event
	if err := json.Unmarshal(eb, &groups); err != nil {
		return nil, nil, err
	}
	var evs []model.Event
	for _, g := range groups {
		evs = append(evs, g...)
	}
	return items, evs, nil
}

// custodyOK checks that transfers form an unbroken sequence starting at u0.
func custodyOK(it ledgerItem, u0 string) bool {
	cur := u0
	for _, x := range it.Transfers {
		if x.From != cur {
			return false
		}
		cur = x.To
	}
	return cur == it.Custodian
}

func sortAlerts(a []Alert) {
	sort.Slice(a, func(i, j int) bool {
		if a[i].GW != a[j].GW {
			return a[i].GW < a[j].GW
		}
		if a[i].Round != a[j].Round {
			return a[i].Round < a[j].Round
		}
		return a[i].Orig < a[j].Orig
	})
}
