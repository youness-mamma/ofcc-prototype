package systems

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"ofcc/chaincode/model"
	"ofcc/client/internal/sim"
	"ofcc/client/internal/tamper"
)

// Row is one line of the centralized log. H chains rows: H_i = SHA256(H_{i-1} | canonical row).
type Row struct {
	Kind  string `json:"k"` // item | xfer
	GW    int    `json:"gw"`
	Seq   int64  `json:"seq"`
	T     int64  `json:"t"`
	D     string `json:"d"`
	P     string `json:"p,omitempty"` // base64 payload
	Round int    `json:"r"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Prev  string `json:"prev"`
	H     string `json:"h"`
}

func rowHash(r Row) string {
	return model.H([]byte(fmt.Sprintf("CL1|%s|%s|%d|%d|%d|%s|%s|%s|%s", r.Prev, r.Kind, r.GW, r.Seq, r.T, r.D, r.P, r.From, r.To)))
}

// ---------------------------------------------------------------- server (separate process)

type clServer struct {
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	last string
	next map[int]int64
}

type ingestReq struct {
	GW    int       `json:"gw"`
	Round int       `json:"round"`
	Recs  []ingRec  `json:"recs"`
	Xfer  *xferReq  `json:"xfer,omitempty"`
}
type ingRec struct {
	Seq int64  `json:"seq"`
	T   int64  `json:"t"`
	P   string `json:"p"`
}
type xferReq struct {
	Seq  int64  `json:"seq"`
	From string `json:"from"`
	To   string `json:"to"`
}

func (s *clServer) append(r Row) {
	r.Prev = s.last
	r.H = rowHash(r)
	s.last = r.H
	b, _ := json.Marshal(r)
	s.w.Write(b)
	s.w.WriteByte('\n')
}

func (s *clServer) handle(w http.ResponseWriter, req *http.Request) {
	var in ingestReq
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var alerts []string
	if in.Xfer != nil {
		s.append(Row{Kind: "xfer", GW: in.GW, Seq: in.Xfer.Seq, From: in.Xfer.From, To: in.Xfer.To, T: time.Now().UnixNano()})
	}
	for _, r := range in.Recs {
		exp := s.next[in.GW] + 1
		if r.Seq > exp {
			alerts = append(alerts, "gap")
		} else if r.Seq < exp {
			alerts = append(alerts, "dupseq")
		}
		if r.Seq >= exp {
			s.next[in.GW] = r.Seq
		}
		p, _ := base64.StdEncoding.DecodeString(r.P)
		s.append(Row{Kind: "item", GW: in.GW, Seq: r.Seq, T: r.T, D: model.H(p), P: r.P, Round: in.Round})
	}
	s.w.Flush()
	s.f.Sync()
	json.NewEncoder(w).Encode(alerts)
}

// ServeCL runs the centralized log server until killed.
func ServeCL(addr, dbPath string) error {
	f, err := os.Create(dbPath)
	if err != nil {
		return err
	}
	s := &clServer{f: f, w: bufio.NewWriterSize(f, 1<<20), next: map[int]int64{}}
	http.HandleFunc("/ingest", s.handle)
	return http.ListenAndServe(addr, nil)
}

// ---------------------------------------------------------------- client side

// CL is the centralized-log baseline as seen by gateways, the verifier and the insider.
type CL struct {
	URL, DB string
	hc      *http.Client
	mu      sync.Mutex
	anch    map[int]int64
}

func NewCL(url, db string) *CL {
	return &CL{URL: url, DB: db, hc: &http.Client{Timeout: 5 * time.Minute}, anch: map[int]int64{}}
}

func (c *CL) Name() string                    { return "cl" }
func (c *CL) Register(g *sim.Gateway) error   { return nil }
func (c *CL) Repairer(g *sim.Gateway) tamper.Repairer {
	c.mu.Lock()
	defer c.mu.Unlock()
	return tamper.Repairer{Signed: false, Seq: true, AnchorSeq: c.anch[g.Idx]}
}

func (c *CL) post(req ingestReq) ([]string, int64, time.Duration, error) {
	b, _ := json.Marshal(req)
	t0 := time.Now()
	resp, err := c.hc.Post(c.URL+"/ingest", "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, 0, 0, fmt.Errorf("cl ingest status %d", resp.StatusCode)
	}
	var alerts []string
	err = json.NewDecoder(resp.Body).Decode(&alerts)
	return alerts, int64(len(b)), time.Since(t0), err
}

func (c *CL) Sync(g *sim.Gateway, recs []*sim.Record, round int, b int) (SyncOut, error) {
	var out SyncOut
	for _, ch := range chunks(recs, b) {
		req := ingestReq{GW: g.Idx, Round: round}
		for _, r := range ch {
			req.Recs = append(req.Recs, ingRec{Seq: r.Seq, T: r.T, P: base64.StdEncoding.EncodeToString(r.Cipher)})
		}
		alerts, _, lat, err := c.post(req)
		if err != nil {
			return out, err
		}
		// link bytes = raw payload bytes + metadata (excluding base64 expansion), as for the other systems
		meta := req
		meta.Recs = nil
		for _, r := range ch {
			meta.Recs = append(meta.Recs, ingRec{Seq: r.Seq, T: r.T})
			out.LinkBytes += int64(len(r.Cipher))
		}
		mb, _ := json.Marshal(meta)
		out.LinkBytes += int64(len(mb))
		out.Txs++
		out.Lat = append(out.Lat, lat.Seconds())
		for _, a := range alerts {
			out.Alerts = append(out.Alerts, Alert{GW: g.Idx, Round: round, Orig: -1, Kind: a})
		}
	}
	c.mu.Lock()
	for _, r := range recs {
		if r.Seq > c.anch[g.Idx] {
			c.anch[g.Idx] = r.Seq
		}
	}
	c.mu.Unlock()
	return out, nil
}

func (c *CL) Transfer(g *sim.Gateway, r *sim.Record) error {
	if _, _, _, err := c.post(ingestReq{GW: g.Idx, Xfer: &xferReq{Seq: r.Seq, From: collector, To: investigator}}); err != nil {
		return err
	}
	_, _, _, err := c.post(ingestReq{GW: g.Idx, Xfer: &xferReq{Seq: r.Seq, From: investigator, To: investigator2}})
	return err
}

func (c *CL) load() ([]Row, error) {
	f, err := os.Open(c.DB)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []Row
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	for sc.Scan() {
		var r Row
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, sc.Err()
}

func (c *CL) save(rows []Row) error {
	var buf bytes.Buffer
	for _, r := range rows {
		b, _ := json.Marshal(r)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return os.WriteFile(c.DB, buf.Bytes(), 0o644)
}

func rechain(rows []Row, from int) {
	prev := ""
	if from > 0 {
		prev = rows[from-1].H
	}
	for i := from; i < len(rows); i++ {
		rows[i].Prev = prev
		if rows[i].Kind == "item" {
			p, _ := base64.StdEncoding.DecodeString(rows[i].P)
			rows[i].D = model.H(p)
		}
		rows[i].H = rowHash(rows[i])
		prev = rows[i].H
	}
}

// Post tampers with the central database as an insider. An adaptive insider recomputes the chain.
func (c *CL) Post(op *tamper.Op, g *sim.Gateway, target, other *sim.Record, adaptive bool, rng *rand.Rand) error {
	rows, err := c.load()
	if err != nil {
		return err
	}
	idx := -1
	for i, r := range rows {
		if r.Kind == "item" && r.GW == g.Idx && r.D == target.D {
			idx = i
			break
		}
	}
	if idx < 0 {
		op.NA = true
		return nil
	}
	op.Targets = []int64{target.Orig}
	shift := func(from int, delta int64) { // adaptive insider renumbers later rows of the same gateway
		for i := from; i < len(rows); i++ {
			if rows[i].Kind == "item" && rows[i].GW == g.Idx {
				rows[i].Seq += delta
			}
		}
	}
	maxSeq := func() int64 {
		var m int64
		for _, r := range rows {
			if r.Kind == "item" && r.GW == g.Idx && r.Seq > m {
				m = r.Seq
			}
		}
		return m
	}
	switch op.Type {
	case "modEntry":
		rows[idx].T += 1_000_000_000
	case "modPayload":
		p, _ := base64.StdEncoding.DecodeString(rows[idx].P)
		rows[idx].P = base64.StdEncoding.EncodeToString(flip(p, rng))
	case "delete":
		rows = append(rows[:idx:idx], rows[idx+1:]...)
		if adaptive {
			shift(idx, -1)
		}
	case "truncate": // drop the last three rows of the whole log
		op.Targets = nil
		n := len(rows)
		for _, r := range rows[n-3:] {
			if r.Kind == "item" {
				op.Refs = append(op.Refs, tamper.Ref{GW: r.GW, D: r.D})
			}
		}
		rows = rows[:n-3]
	case "insert":
		f := rows[idx]
		p, _ := base64.StdEncoding.DecodeString(f.P)
		f.P = base64.StdEncoding.EncodeToString(flip(p, rng))
		rows = append(rows[:idx:idx], append([]Row{f}, rows[idx:]...)...)
		if adaptive {
			shift(idx+1, 1)
		}
	case "reorder":
		j := idx + 1
		for j < len(rows) && !(rows[j].Kind == "item" && rows[j].GW == g.Idx) {
			j++
		}
		if j >= len(rows) {
			op.NA = true
			return nil
		}
		rows[idx], rows[j] = rows[j], rows[idx]
		if adaptive {
			rows[idx].Seq, rows[j].Seq = rows[j].Seq, rows[idx].Seq
		}
	case "replay":
		r := rows[idx]
		if adaptive {
			r.Seq = maxSeq() + 1
		}
		rows = append(rows, r)
	}
	if adaptive {
		rechain(rows, 0)
	}
	return c.save(rows)
}

func (c *CL) Verify(gws []*sim.Gateway, t *Truth) (VerifyOut, error) {
	out := VerifyOut{Complete: map[int]map[int64]bool{}}
	rows, err := c.load()
	if err != nil {
		return out, err
	}
	brk := len(rows)
	prev := ""
	for i, r := range rows {
		d := r.D
		if r.Kind == "item" {
			p, _ := base64.StdEncoding.DecodeString(r.P)
			d = model.H(p)
		}
		if r.Prev != prev || rowHash(r) != r.H || d != r.D {
			o, rd := t.orig(r.GW, r.D)
			out.Alerts = append(out.Alerts, Alert{GW: r.GW, Round: rd, Orig: o, Kind: "chain"})
			brk = i
			break
		}
		prev = r.H
	}
	// sequence check per gateway over the stored log
	last := map[int]int64{}
	seen := map[[2]int64]bool{}
	cust := map[[2]int64]string{}
	for _, r := range rows[:brk] {
		k := [2]int64{int64(r.GW), r.Seq}
		if r.Kind == "xfer" {
			if cust[k] == "" {
				cust[k] = collector
			}
			if cust[k] != r.From {
				cust[k] = "broken"
			} else {
				cust[k] = r.To
			}
			continue
		}
		if seen[k] {
			o, rd := t.orig(r.GW, r.D)
			out.Alerts = append(out.Alerts, Alert{GW: r.GW, Round: rd, Orig: o, Kind: "dupseq"})
		}
		seen[k] = true
		if r.Seq > last[r.GW]+1 {
			for s := last[r.GW] + 1; s < r.Seq; s++ {
				out.Alerts = append(out.Alerts, Alert{GW: r.GW, Round: t.roundOf(r.GW, s), Orig: s, Kind: "gap"})
			}
		}
		if r.Seq > last[r.GW] {
			last[r.GW] = r.Seq
		}
	}
	for _, r := range rows[:brk] {
		if r.Kind != "item" {
			continue
		}
		o, _ := t.orig(r.GW, r.D)
		if o < 0 {
			continue
		}
		if out.Complete[r.GW] == nil {
			out.Complete[r.GW] = map[int64]bool{}
		}
		if cs := cust[[2]int64{int64(r.GW), r.Seq}]; cs != "broken" {
			out.Complete[r.GW][o] = true
		}
	}
	sortAlerts(out.Alerts)
	return out, nil
}
