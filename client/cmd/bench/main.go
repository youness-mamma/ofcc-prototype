// Command bench runs the OFCC experiments. Every run writes one JSON file.
//
//	bench bootstrap -crypto DIR
//	bench clserver  -addr 127.0.0.1:7070 -db FILE
//	bench e1 ...    detection, custody completeness, storage and cost (tampering with ground truth)
//	bench e2 ...    synchronization time vs outage length
//	bench e3 ...    throughput and latency at fixed offered loads
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"ofcc/chaincode/model"
	"ofcc/client/internal/fab"
	"ofcc/client/internal/metrics"
	"ofcc/client/internal/sim"
	"ofcc/client/internal/store"
	"ofcc/client/internal/systems"
	"ofcc/client/internal/tamper"
)

type common struct {
	crypto, minioEP, minioUser, minioPass, minioData, out, system string
	seed                                                         int64
	b, gws                                                       int
	orgs                                                         int
	batchTimeout                                                 string
}

func (c *common) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.crypto, "crypto", "network/build/crypto", "crypto material dir")
	fs.StringVar(&c.minioEP, "minio", "127.0.0.1:9000", "MinIO endpoint")
	fs.StringVar(&c.minioUser, "minio-user", "ofccadmin", "")
	fs.StringVar(&c.minioPass, "minio-pass", "ofccadmin-secret", "")
	fs.StringVar(&c.minioData, "minio-data", "minio-data", "MinIO data dir (for storage)")
	fs.StringVar(&c.out, "out", "results/raw", "output dir")
	fs.StringVar(&c.system, "system", "ofcc", "ofcc|noChain|noSig|noSeq|noEnc|ha|cl")
	fs.Int64Var(&c.seed, "seed", 1, "seed")
	fs.IntVar(&c.b, "b", 100, "batch size (entries per transaction)")
	fs.IntVar(&c.gws, "gws", 8, "number of gateways")
	fs.IntVar(&c.orgs, "orgs", 4, "number of organizations (recorded only)")
	fs.StringVar(&c.batchTimeout, "bt", "1s", "orderer batch timeout (recorded only)")
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func salt(s string) int64 { h := fnv.New64a(); h.Write([]byte(s)); return int64(h.Sum64() >> 2) }

func conns(crypto string) *systems.Conns {
	c := &systems.Conns{}
	var err error
	c.Admin, err = fab.Connect(crypto, 1, "Admin")
	must(err)
	c.Gateway, err = fab.Connect(crypto, 1, "User4")
	must(err)
	c.Collector, err = fab.Connect(crypto, 1, "User1")
	must(err)
	c.Investigator, err = fab.Connect(crypto, 1, "User2")
	must(err)
	c.Investigator2, err = fab.Connect(crypto, 2, "User2")
	must(err)
	c.Auditor, err = fab.Connect(crypto, 1, "User3")
	must(err)
	return c
}

type clProc struct {
	cmd *exec.Cmd
	db  string
}

func startCL(dir string) (*clProc, *systems.CL) {
	self, _ := os.Executable()
	db := filepath.Join(dir, fmt.Sprintf("cl-%d.jsonl", time.Now().UnixNano()))
	cmd := exec.Command(self, "clserver", "-addr", "127.0.0.1:7070", "-db", db)
	cmd.Stderr = os.Stderr
	must(cmd.Start())
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", "127.0.0.1:7070"); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return &clProc{cmd: cmd, db: db}, systems.NewCL("http://127.0.0.1:7070", db)
}

func (p *clProc) stop() { p.cmd.Process.Kill(); p.cmd.Wait() }

// newSystem builds the system under test; for cl it also starts the server process.
func newSystem(c *common, cs *systems.Conns, bucket string) (systems.System, model.Mode, *clProc) {
	if c.system == "cl" {
		p, s := startCL(os.TempDir())
		return s, model.Mode{Name: "cl", Enc: true}, p
	}
	m, err := model.ModeByName(c.system)
	must(err)
	st, err := store.New(c.minioEP, c.minioUser, c.minioPass, bucket)
	must(err)
	return systems.NewLedger(m, cs, st), m, nil
}

type cpuSnap struct{ fabric, client, minio, clsrv float64 }

func snap(minioPID int, cl *clProc) cpuSnap {
	f, _ := metrics.ContainerCPU("example.com", "dev-peer")
	s := cpuSnap{fabric: f, client: metrics.SelfCPU()}
	if minioPID > 0 {
		s.minio = metrics.ProcCPU(minioPID)
	}
	if cl != nil {
		s.clsrv = metrics.ProcCPU(cl.cmd.Process.Pid)
	}
	return s
}

func ledgerBytes(orgs int) int64 {
	var t int64
	for i := 1; i <= orgs; i++ {
		// append-only block files
		if v := metrics.VolumeBytes(fmt.Sprintf("peer0.org%d.example.com", i), "/var/hyperledger/production/ledgersData/chains"); v > 0 {
			t += v
		}
	}
	return t
}

func env() map[string]string {
	return map[string]string{"cpu_model": metrics.CPUModel(), "ncpu": fmt.Sprint(runtime.NumCPU()),
		"go": runtime.Version(), "commit": os.Getenv("GITHUB_SHA"), "runner": os.Getenv("RUNNER_NAME"),
		"fabric": os.Getenv("FABRIC_VERSION"), "minio": os.Getenv("MINIO_RELEASE"), "time": time.Now().UTC().Format(time.RFC3339)}
}

func writeJSON(dir, name string, v any) {
	must(os.MkdirAll(dir, 0o755))
	b, _ := json.MarshalIndent(v, "", " ")
	must(os.WriteFile(filepath.Join(dir, name), b, 0o644))
	fmt.Println("wrote", filepath.Join(dir, name))
}

func minioPID() int {
	out, err := exec.Command("pgrep", "-f", "minio server").Output()
	if err != nil {
		return 0
	}
	var pid int
	fmt.Sscan(strings.Fields(string(out))[0], &pid)
	return pid
}

// ---------------------------------------------------------------- bootstrap

func bootstrap(args []string) {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	crypto := fs.String("crypto", "network/build/crypto", "")
	fs.Parse(args)
	a, err := fab.Connect(*crypto, 1, "Admin")
	must(err)
	roles := map[string]string{"User1@org1.example.com": "collector", "User2@org1.example.com": "investigator",
		"User2@org2.example.com": "investigator", "User3@org1.example.com": "auditor", "User4@org1.example.com": "gateway"}
	rb, _ := json.Marshal(roles)
	_, _, _, err = a.Submit("Bootstrap", string(rb), "10", "5")
	must(err)
	fmt.Println("BOOTSTRAP_OK")
}

// ---------------------------------------------------------------- E1

type e1Result struct {
	Exp        string            `json:"exp"`
	System     string            `json:"system"`
	Seed       int64             `json:"seed"`
	Adversary  string            `json:"adversary"`
	Config     map[string]any    `json:"config"`
	Env        map[string]string `json:"env"`
	Items      int               `json:"items"`
	Ops        []*tamper.Op      `json:"ops"`
	Untouched  int               `json:"untouched_items"`
	Complete   int               `json:"complete_untouched_items"`
	FAItems    int               `json:"false_alarm_items"`
	CleanRnds  int               `json:"clean_rounds"`
	FARounds   int               `json:"clean_rounds_with_alert"`
	Transfers  int               `json:"transfers_ok"`
	TransferEr int               `json:"transfer_errors"`
	LinkBytes  int64             `json:"link_bytes"`
	Txs        int               `json:"txs"`
	Storage    map[string]int64  `json:"storage_bytes"`
	CPU        map[string]float64 `json:"cpu_seconds"` // capture + synchronization phase only
	CPUVerify  map[string]float64 `json:"cpu_seconds_verify"`
	SyncWall   float64           `json:"sync_phase_wall_seconds"`
	WallSec    float64           `json:"wall_seconds"`
	Alerts     []systems.Alert   `json:"alerts"`
	Incomplete [][2]int64        `json:"incomplete_untouched_sample"`
	XferErrMsg []string          `json:"transfer_error_messages"`
}

func e1(args []string) {
	fs := flag.NewFlagSet("e1", flag.ExitOnError)
	var c common
	c.flags(fs)
	rounds := fs.Int("rounds", 40, "sync rounds per gateway")
	perType := fs.Int("pre", 20, "pre-upload operations per type")
	postType := fs.Int("post", 10, "post-upload operations per type")
	adv := fs.String("adversary", "adaptive", "naive|adaptive")
	xferFrac := fs.Float64("xfer", 0.02, "fraction of clean items with two custody transfers")
	fs.Parse(args)
	adaptive := *adv == "adaptive"
	cs := conns(c.crypto)
	bucket := strings.ToLower(fmt.Sprintf("e1-%s-%d-%s", c.system, c.seed, *adv))
	sys, mode, clp := newSystem(&c, cs, bucket)
	if clp != nil {
		defer clp.stop()
	}

	// workload: identical across systems for a given seed
	wr := rand.New(rand.NewSource(c.seed))
	sizes := make([][]int, c.gws)
	maxItems := 0
	for g := range sizes {
		tot := 0
		sizes[g] = make([]int, *rounds)
		for r := range sizes[g] {
			sizes[g][r] = 20 + wr.Intn(41) // offline period of 20-60 s at one item per second
			tot += sizes[g][r]
		}
		if tot > maxItems {
			maxItems = tot
		}
	}
	// pre-upload operation schedule: only odd rounds 1..R-3, so tampered rounds are never adjacent,
	// round 0 is clean (replay needs history) and the round after each tampered round exists and is clean.
	var slots [][2]int
	for g := 0; g < c.gws; g++ {
		for r := 1; r <= *rounds-3; r += 2 {
			slots = append(slots, [2]int{g, r})
		}
	}
	sr := rand.New(rand.NewSource(c.seed*31 + 7))
	sr.Shuffle(len(slots), func(i, j int) { slots[i], slots[j] = slots[j], slots[i] })
	pre := map[[2]int]*tamper.Op{}
	if len(slots) < len(tamper.Ops)**perType {
		must(fmt.Errorf("not enough non-adjacent slots (%d) for %d operations", len(slots), len(tamper.Ops)**perType))
	}
	k := 0
	for _, t := range tamper.Ops {
		for i := 0; i < *perType && k < len(slots); i++ {
			s := slots[k]
			pre[s] = &tamper.Op{Type: t, Pos: "pre", GW: s[0], Round: s[1]}
			k++
		}
	}

	truth := systems.NewTruth()
	gws := make([]*sim.Gateway, c.gws)
	for i := range gws {
		gws[i] = sim.New(i, mode, c.seed, salt(bucket))
		must(sys.Register(gws[i]))
	}
	t0 := time.Now().Add(-time.Duration(maxItems+120) * time.Second).UnixNano()
	cpu0 := snap(minioPID(), clp)
	led0 := ledgerBytes(c.orgs)
	start := time.Now()

	var mu sync.Mutex
	var alerts []systems.Alert
	var link int64
	var txs int
	clean := map[int][]*sim.Record{} // gw -> records of clean rounds
	var wg sync.WaitGroup
	errc := make(chan error, c.gws)
	for gi := range gws {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			g := gws[gi]
			var hist []*sim.Record
			compromised := false // adaptive adversary keeps normalizing an unsigned store once it controls it
			vt := t0
			for r := 0; r < *rounds; r++ {
				recs := make([]*sim.Record, sizes[gi][r])
				for i := range recs {
					vt += int64(time.Second)
					recs[i] = g.Capture(vt)
					truth.Add(recs[i], r)
				}
				if op, ok := pre[[2]int{gi, r}]; ok {
					orng := rand.New(rand.NewSource(c.seed*1009 + int64(gi)*97 + int64(r)))
					recs = tamper.ApplyPre(op, recs, hist, adaptive, sys.Repairer(g), orng)
					compromised = adaptive
				} else {
					if compromised {
						if rp := sys.Repairer(g); !rp.Signed {
							rp.Repair(recs)
						}
					}
					// items outside every detection window are the pool for transfers and post-upload targets
					if _, prevTampered := pre[[2]int{gi, r - 1}]; !prevTampered {
						mu.Lock()
						clean[gi] = append(clean[gi], recs...)
						mu.Unlock()
					}
				}
				out, err := sys.Sync(g, recs, r, c.b)
				if err != nil {
					errc <- fmt.Errorf("gw %d round %d: %w", gi, r, err)
					return
				}
				mu.Lock()
				alerts, link, txs = append(alerts, out.Alerts...), link+out.LinkBytes, txs+out.Txs
				mu.Unlock()
				for _, x := range recs {
					if !x.Forged {
						cp := *x
						hist = append(hist, &cp)
					}
				}
			}
		}(gi)
	}
	wg.Wait()
	close(errc)
	if err := <-errc; err != nil {
		must(err)
	}
	syncWall := time.Since(start).Seconds()
	cpuSync := snap(minioPID(), clp) // capture + synchronization only (normal operation)

	// custody transfers and post-upload tampering on clean-round items (disjoint sets)
	pr := rand.New(rand.NewSource(c.seed*53 + 11))
	used := map[[2]int64]bool{}
	pick := func() (int, *sim.Record, *sim.Record) {
		for {
			gi := pr.Intn(c.gws)
			l := clean[gi]
			a, b := l[pr.Intn(len(l))], l[pr.Intn(len(l))]
			if a != b && !used[[2]int64{int64(gi), a.Orig}] {
				used[[2]int64{int64(gi), a.Orig}] = true
				return gi, a, b
			}
		}
	}
	nClean := 0
	for _, l := range clean {
		nClean += len(l)
	}
	xok, xerr := 0, 0
	var xmsgs []string
	var xwg sync.WaitGroup
	var xmu sync.Mutex
	sem := make(chan struct{}, 8)
	for i := 0; i < int(float64(nClean)**xferFrac); i++ {
		gi, a, _ := pick()
		xwg.Add(1)
		sem <- struct{}{}
		go func(gi int, a *sim.Record) {
			defer xwg.Done()
			defer func() { <-sem }()
			err := sys.Transfer(gws[gi], a) // each step retried inside Transfer
			xmu.Lock()
			if err != nil {
				xerr++
				if len(xmsgs) < 5 {
					xmsgs = append(xmsgs, err.Error())
				}
			} else {
				xok++
			}
			xmu.Unlock()
		}(gi, a)
	}
	xwg.Wait()
	var ops []*tamper.Op
	for _, op := range pre {
		ops = append(ops, op)
	}
	for _, t := range tamper.Ops {
		for i := 0; i < *postType; i++ {
			gi, a, b := pick()
			op := &tamper.Op{Type: t, Pos: "post", GW: gi, Round: truth.RoundOf[gi][a.Orig]}
			must(sys.Post(op, gws[gi], a, b, adaptive, pr))
			for _, ref := range op.Refs { // cross-gateway targets (CL truncate)
				if o, ok := truth.OrigOf[ref.GW][ref.D]; ok && ref.GW == gi {
					op.Targets = append(op.Targets, o)
				}
			}
			ops = append(ops, op)
		}
	}
	cpuV0 := snap(minioPID(), clp)
	vout, err := sys.Verify(gws, truth)
	must(err)
	wall := time.Since(start).Seconds()
	cpuV1 := snap(minioPID(), clp)
	led1 := ledgerBytes(c.orgs)
	var off int64
	if l, ok := sys.(*systems.Ledger); ok {
		off = l.OffchainBytes()
	}

	// ----- scoring against ground truth
	all := append(alerts, vout.Alerts...)
	touched := map[[2]int64]bool{}
	preRound := map[[2]int]bool{}  // rounds with a pre-upload operation
	nextRound := map[[2]int]bool{} // the following round (detection window, excluded from false alarms)
	for _, op := range ops {
		if op.Pos == "pre" {
			preRound[[2]int{op.GW, op.Round}] = true
			nextRound[[2]int{op.GW, op.Round + 1}] = true
		}
		for _, t := range op.Targets {
			touched[[2]int64{int64(op.GW), t}] = true
		}
		for _, ref := range op.Refs {
			if o, ok := truth.OrigOf[ref.GW][ref.D]; ok {
				touched[[2]int64{int64(ref.GW), o}] = true
			}
		}
	}
	for _, op := range ops {
		if op.NA {
			continue
		}
		for _, a := range all {
			if a.GW != op.GW && op.Pos == "pre" {
				continue
			}
			if op.Pos == "pre" && (a.Round == op.Round || a.Round == op.Round+1) { // same or next sync
				op.Detected = true
			}
			if op.Pos == "post" {
				if op.Key != "" && a.Key == op.Key {
					op.Detected = true
				}
				for _, t := range op.Targets {
					if a.GW == op.GW && a.Orig == t {
						op.Detected = true
					}
				}
				for _, ref := range op.Refs {
					if o, ok := truth.OrigOf[ref.GW][ref.D]; ok && a.GW == ref.GW && a.Orig == o {
						op.Detected = true
					}
				}
			}
		}
	}
	items, untouched, complete := 0, 0, 0
	var incomplete [][2]int64
	for gi := 0; gi < c.gws; gi++ {
		for o, r := range truth.RoundOf[gi] {
			items++
			if preRound[[2]int{gi, r}] || touched[[2]int64{int64(gi), o}] {
				continue
			}
			untouched++
			if vout.Complete[gi][o] {
				complete++
			} else if len(incomplete) < 50 {
				incomplete = append(incomplete, [2]int64{int64(gi), o})
			}
		}
	}
	faItems := map[[2]int64]bool{}
	faRounds := map[[2]int]bool{}
	cleanRounds := 0
	for gi := 0; gi < c.gws; gi++ {
		for r := 0; r < *rounds; r++ {
			if !preRound[[2]int{gi, r}] && !nextRound[[2]int{gi, r}] {
				cleanRounds++
			}
		}
	}
	for _, a := range all {
		if a.Orig >= 0 && !touched[[2]int64{int64(a.GW), a.Orig}] && !preRound[[2]int{a.GW, a.Round}] && !nextRound[[2]int{a.GW, a.Round}] {
			faItems[[2]int64{int64(a.GW), a.Orig}] = true
		}
		if a.Round >= 0 && !preRound[[2]int{a.GW, a.Round}] && !nextRound[[2]int{a.GW, a.Round}] && a.Orig < 0 && a.Key == "" {
			faRounds[[2]int{a.GW, a.Round}] = true
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Pos != ops[j].Pos {
			return ops[i].Pos > ops[j].Pos
		}
		if ops[i].GW != ops[j].GW {
			return ops[i].GW < ops[j].GW
		}
		return ops[i].Round < ops[j].Round
	})
	res := e1Result{Exp: "e1", System: c.system, Seed: c.seed, Adversary: *adv, Env: env(),
		Config: map[string]any{"gws": c.gws, "rounds": *rounds, "pre_per_type": *perType, "post_per_type": *postType,
			"b": c.b, "orgs": c.orgs, "batch_timeout": c.batchTimeout, "xfer_frac": *xferFrac, "items_per_round": "20-60",
			"detection_window": "same or next sync of the gateway", "pre_op_rounds": "odd rounds 1..R-3"},
		Items: items, Ops: ops, Untouched: untouched, Complete: complete, FAItems: len(faItems),
		CleanRnds: cleanRounds, FARounds: len(faRounds), Transfers: xok, TransferEr: xerr, LinkBytes: link, Txs: txs,
		Storage: map[string]int64{"ledger_blocks_all_peers": led1 - led0, "offchain": off},
		CPU: map[string]float64{"fabric": cpuSync.fabric - cpu0.fabric, "client": cpuSync.client - cpu0.client,
			"minio": cpuSync.minio - cpu0.minio, "cl_server": cpuSync.clsrv - cpu0.clsrv},
		CPUVerify: map[string]float64{"fabric": cpuV1.fabric - cpuV0.fabric, "client": cpuV1.client - cpuV0.client,
			"minio": cpuV1.minio - cpuV0.minio},
		SyncWall: syncWall, WallSec: wall, Alerts: all, Incomplete: incomplete, XferErrMsg: xmsgs}
	if clp != nil {
		if fi, err := os.Stat(clp.db); err == nil {
			res.Storage["cl_db"] = fi.Size()
		}
	}
	writeJSON(c.out, fmt.Sprintf("e1_%s_%s_seed%d.json", c.system, *adv, c.seed), res)
}

// ---------------------------------------------------------------- E2

func e2(args []string) {
	fs := flag.NewFlagSet("e2", flag.ExitOnError)
	var c common
	c.flags(fs)
	dl := fs.String("outages", "1,2,5,10,20", "outage lengths in minutes")
	tag := fs.String("tag", "", "extra tag in file name")
	fs.Parse(args)
	cs := conns(c.crypto)
	type row struct {
		OutageMin  int     `json:"outage_min"`
		Items      int     `json:"items"`
		SyncSec    float64 `json:"sync_seconds"`
		Txs        int     `json:"txs"`
		LinkBytes  int64   `json:"link_bytes"`
		TxLatP50   float64 `json:"tx_latency_p50"`
		TxLatP95   float64 `json:"tx_latency_p95"`
	}
	var rows []row
	for _, ds := range strings.Split(*dl, ",") {
		var d int
		fmt.Sscan(ds, &d)
		bucket := strings.ToLower(fmt.Sprintf("e2-%s-%d-d%d%s", c.system, c.seed, d, *tag))
		sys, mode, clp := newSystem(&c, cs, bucket)
		gws := make([]*sim.Gateway, c.gws)
		recs := make([][]*sim.Record, c.gws)
		n := 60 * d
		t0 := time.Now().Add(-time.Duration(n+120) * time.Second).UnixNano()
		for i := range gws {
			gws[i] = sim.New(i, mode, c.seed, salt(bucket))
			must(sys.Register(gws[i]))
			for j := 0; j < n; j++ {
				recs[i] = append(recs[i], gws[i].Capture(t0+int64(j+1)*int64(time.Second)))
			}
		}
		var mu sync.Mutex
		var lats []float64
		var link int64
		txs := 0
		var wg sync.WaitGroup
		start := time.Now()
		for i := range gws {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				out, err := sys.Sync(gws[i], recs[i], 0, c.b)
				must(err)
				mu.Lock()
				lats, link, txs = append(lats, out.Lat...), link+out.LinkBytes, txs+out.Txs
				mu.Unlock()
			}(i)
		}
		wg.Wait()
		el := time.Since(start).Seconds()
		if clp != nil {
			clp.stop()
		}
		sort.Float64s(lats)
		rows = append(rows, row{OutageMin: d, Items: n * c.gws, SyncSec: el, Txs: txs, LinkBytes: link,
			TxLatP50: pct(lats, 0.5), TxLatP95: pct(lats, 0.95)})
		fmt.Printf("e2 %s D=%d items=%d sync=%.2fs\n", c.system, d, n*c.gws, el)
	}
	writeJSON(c.out, fmt.Sprintf("e2_%s_seed%d%s.json", c.system, c.seed, *tag), map[string]any{
		"exp": "e2", "system": c.system, "seed": c.seed, "env": env(),
		"config": map[string]any{"gws": c.gws, "b": c.b, "orgs": c.orgs, "batch_timeout": c.batchTimeout, "rate_items_per_s": 1},
		"rows": rows})
}

func pct(s []float64, p float64) float64 {
	if len(s) == 0 {
		return 0
	}
	i := int(p*float64(len(s)-1) + 0.5)
	return s[i]
}

// ---------------------------------------------------------------- E3

func e3(args []string) {
	fs := flag.NewFlagSet("e3", flag.ExitOnError)
	var c common
	c.flags(fs)
	loads := fs.String("loads", "50,100,200,400", "offered loads, items/s")
	warm := fs.Duration("warmup", 60*time.Second, "")
	meas := fs.Duration("measure", 180*time.Second, "")
	pool := fs.Int("pool", 32, "gateways in the load generator")
	tag := fs.String("tag", "", "")
	fs.Parse(args)
	cs := conns(c.crypto)
	type row struct {
		Load       int     `json:"offered_items_per_s"`
		Throughput float64 `json:"throughput_items_per_s"`
		LatMean    float64 `json:"latency_mean_s"`
		LatP50     float64 `json:"latency_p50_s"`
		LatP95     float64 `json:"latency_p95_s"`
		Batches    int     `json:"batches_in_window"`
		Errors     int     `json:"errors"`
		CPU        map[string]float64 `json:"cpu_seconds"`
	}
	var rows []row
	for _, ls := range strings.Split(*loads, ",") {
		var L int
		fmt.Sscan(ls, &L)
		bucket := strings.ToLower(fmt.Sprintf("e3-%s-%d-l%d%s", c.system, c.seed, L, *tag))
		sys, mode, clp := newSystem(&c, cs, bucket)
		gws := make([]*sim.Gateway, *pool)
		locks := make([]sync.Mutex, *pool)
		for i := range gws {
			gws[i] = sim.New(i, mode, c.seed+int64(L), salt(bucket))
			must(sys.Register(gws[i]))
		}
		interval := time.Duration(float64(time.Second) * float64(c.b) / float64(L))
		start := time.Now()
		ws, we := start.Add(*warm), start.Add(*warm+*meas)
		type res struct {
			sched, done time.Time
			ok          bool
		}
		resc := make(chan res, 1<<16)
		var wg sync.WaitGroup
		cpu0 := snap(minioPID(), clp)
		var cpuW0 cpuSnap
		gotW0 := false
		next := 0
		for t := start; t.Before(we); t = t.Add(interval) {
			time.Sleep(time.Until(t))
			if !gotW0 && !t.Before(ws) {
				cpuW0, gotW0 = snap(minioPID(), clp), true
			}
			gi := next % *pool
			next++
			wg.Add(1)
			go func(sched time.Time, gi int) {
				defer wg.Done()
				locks[gi].Lock()
				defer locks[gi].Unlock()
				g := gws[gi]
				recs := make([]*sim.Record, c.b)
				for j := range recs {
					recs[j] = g.Capture(time.Now().UnixNano())
				}
				_, err := sys.Sync(g, recs, 0, c.b)
				resc <- res{sched: sched, done: time.Now(), ok: err == nil}
			}(t, gi)
		}
		cpuW1 := snap(minioPID(), clp)
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(120 * time.Second):
		}
		close(resc)
		var lats []float64
		committed, nb, errs := 0, 0, 0
		for r := range resc {
			if !r.ok {
				errs++
				continue
			}
			if !r.done.Before(ws) && r.done.Before(we) {
				committed += c.b
			}
			if !r.sched.Before(ws) && r.sched.Before(we) {
				lats = append(lats, r.done.Sub(r.sched).Seconds())
				nb++
			}
		}
		sort.Float64s(lats)
		mean := 0.0
		for _, x := range lats {
			mean += x
		}
		if len(lats) > 0 {
			mean /= float64(len(lats))
		}
		if clp != nil {
			clp.stop()
		}
		_ = cpu0
		rows = append(rows, row{Load: L, Throughput: float64(committed) / meas.Seconds(), LatMean: mean,
			LatP50: pct(lats, 0.5), LatP95: pct(lats, 0.95), Batches: nb, Errors: errs,
			CPU: map[string]float64{"fabric": cpuW1.fabric - cpuW0.fabric, "client": cpuW1.client - cpuW0.client,
				"minio": cpuW1.minio - cpuW0.minio, "cl_server": cpuW1.clsrv - cpuW0.clsrv, "window_s": meas.Seconds()}})
		fmt.Printf("e3 %s L=%d thr=%.1f p50=%.3f p95=%.3f errs=%d\n", c.system, L, float64(committed)/meas.Seconds(), pct(lats, 0.5), pct(lats, 0.95), errs)
	}
	writeJSON(c.out, fmt.Sprintf("e3_%s_orgs%d_seed%d%s.json", c.system, c.orgs, c.seed, *tag), map[string]any{
		"exp": "e3", "system": c.system, "seed": c.seed, "env": env(),
		"config": map[string]any{"b": c.b, "orgs": c.orgs, "batch_timeout": c.batchTimeout, "pool": *pool,
			"warmup_s": warm.Seconds(), "measure_s": meas.Seconds(),
			"latency": "commit time minus scheduled submission time of the batch (includes queueing and payload upload)"},
		"rows": rows})
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: bench bootstrap|clserver|e1|e2|e3 ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "bootstrap":
		bootstrap(os.Args[2:])
	case "clserver":
		fs := flag.NewFlagSet("clserver", flag.ExitOnError)
		addr := fs.String("addr", "127.0.0.1:7070", "")
		db := fs.String("db", "cl.jsonl", "")
		fs.Parse(os.Args[2:])
		must(systems.ServeCL(*addr, *db))
	case "e1":
		e1(os.Args[2:])
	case "e2":
		e2(os.Args[2:])
	case "e3":
		e3(os.Args[2:])
	default:
		fmt.Println("unknown command")
		os.Exit(2)
	}
}
