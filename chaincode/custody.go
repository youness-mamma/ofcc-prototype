// Custody chaincode: anchors gateway batches under rules V0-V4, records gaps, duplicates,
// conflicts, reorders and time flags, keeps custody transfers, and enforces the role policy.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"

	"ofcc/chaincode/model"
)

type Contract struct{ contractapi.Contract }

type Config struct {
	EpsSec   int64 `json:"eps"`   // peer clock tolerance epsilon
	DeltaSec int64 `json:"delta"` // gateway clock bound delta
}

type Gateway struct {
	Pub     string     `json:"pub"`
	Mode    model.Mode `json:"mode"`
	A       int64      `json:"a"`  // anchored head sequence number
	Ha      string     `json:"ha"` // anchored head hash
	Tlast   int64      `json:"tlast"`
	U0      string     `json:"u0"` // initial custodian (collector)
	NAccept int64      `json:"nacc"`
}

type Transfer struct {
	From string `json:"from"`
	To   string `json:"to"`
	Ts   int64  `json:"ts"`
}

type Item struct {
	Seq       int64      `json:"seq"`
	H         string     `json:"h"`
	D         string     `json:"d"`
	T         int64      `json:"t"`
	TimeFlag  bool       `json:"tf,omitempty"`
	Tx        string     `json:"tx"`
	Custodian string     `json:"cust"`
	Transfers []Transfer `json:"xfer,omitempty"`
}

// ---------------------------------------------------------------- identity & roles

func callerCN(ctx contractapi.TransactionContextInterface) (string, *x509.Certificate, error) {
	c, err := ctx.GetClientIdentity().GetX509Certificate()
	if err != nil {
		return "", nil, err
	}
	return c.Subject.CommonName, c, nil
}

func isAdmin(c *x509.Certificate) bool {
	for _, ou := range c.Subject.OrganizationalUnit {
		if ou == "admin" {
			return true
		}
	}
	return false
}

func role(ctx contractapi.TransactionContextInterface) (string, string, error) {
	cn, c, err := callerCN(ctx)
	if err != nil {
		return "", "", err
	}
	if isAdmin(c) {
		return cn, "admin", nil
	}
	b, err := ctx.GetStub().GetState("role:" + cn)
	if err != nil || b == nil {
		return cn, "", fmt.Errorf("no role for %s", cn)
	}
	return cn, string(b), nil
}

func require(ctx contractapi.TransactionContextInterface, allowed ...string) (string, error) {
	cn, r, err := role(ctx)
	if err != nil {
		return "", err
	}
	for _, a := range allowed {
		if r == a {
			return cn, nil
		}
	}
	return "", fmt.Errorf("role %q of %s not allowed", r, cn)
}

// Bootstrap sets the role table (CN -> role) and the clock bounds. Admin only.
func (c *Contract) Bootstrap(ctx contractapi.TransactionContextInterface, rolesJSON string, eps int64, delta int64) error {
	if _, err := require(ctx, "admin"); err != nil {
		return err
	}
	var roles map[string]string
	if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
		return err
	}
	keys := make([]string, 0, len(roles))
	for k := range roles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch roles[k] {
		case "gateway", "collector", "investigator", "auditor":
		default:
			return fmt.Errorf("bad role %q", roles[k])
		}
		if err := ctx.GetStub().PutState("role:"+k, []byte(roles[k])); err != nil {
			return err
		}
	}
	b, _ := json.Marshal(Config{EpsSec: eps, DeltaSec: delta})
	return ctx.GetStub().PutState("config", b)
}

// RegisterGateway records a gateway's public key, mode and initial custodian. Admin only.
func (c *Contract) RegisterGateway(ctx contractapi.TransactionContextInterface, pubB64 string, mode string, u0 string) (string, error) {
	if _, err := require(ctx, "admin"); err != nil {
		return "", err
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("bad public key")
	}
	m, err := model.ModeByName(mode)
	if err != nil {
		return "", err
	}
	pg := model.Pseudonym(pub)
	if b, _ := ctx.GetStub().GetState("gw:" + pg); b != nil {
		return "", fmt.Errorf("gateway exists")
	}
	g := Gateway{Pub: pubB64, Mode: m, A: 0, Ha: model.Genesis(pg), U0: u0}
	b, _ := json.Marshal(g)
	return pg, ctx.GetStub().PutState("gw:"+pg, b)
}

// ---------------------------------------------------------------- helpers

func getGW(ctx contractapi.TransactionContextInterface, pg string) (*Gateway, error) {
	b, err := ctx.GetStub().GetState("gw:" + pg)
	if err != nil || b == nil {
		return nil, fmt.Errorf("unknown gateway %s", pg)
	}
	var g Gateway
	return &g, json.Unmarshal(b, &g)
}

func itemKey(ctx contractapi.TransactionContextInterface, pg, id string) (string, error) {
	return ctx.GetStub().CreateCompositeKey("item", []string{pg, id})
}

func seqID(s int64) string { return fmt.Sprintf("%016d", s) }

func putItem(ctx contractapi.TransactionContextInterface, pg, id string, it Item) error {
	k, err := itemKey(ctx, pg, id)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(it)
	return ctx.GetStub().PutState(k, b)
}

func getItem(ctx contractapi.TransactionContextInterface, pg, id string) (*Item, error) {
	k, err := itemKey(ctx, pg, id)
	if err != nil {
		return nil, err
	}
	b, err := ctx.GetStub().GetState(k)
	if err != nil || b == nil {
		return nil, err
	}
	var it Item
	return &it, json.Unmarshal(b, &it)
}

func putEvents(ctx contractapi.TransactionContextInterface, pg string, ev []model.Event) error {
	if len(ev) == 0 {
		return nil
	}
	k, err := ctx.GetStub().CreateCompositeKey("evt", []string{pg, ctx.GetStub().GetTxID()})
	if err != nil {
		return err
	}
	b, _ := json.Marshal(ev)
	return ctx.GetStub().PutState(k, b)
}

func txTime(ctx contractapi.TransactionContextInterface, cfg Config) (int64, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0, err
	}
	tau := ts.AsTime().UnixNano()
	// Endorsing peer check: reject proposals whose timestamp is more than eps from the peer clock.
	if d := time.Now().UnixNano() - tau; d > cfg.EpsSec*1e9 || -d > cfg.EpsSec*1e9 {
		return 0, fmt.Errorf("transaction timestamp outside peer tolerance")
	}
	return tau, nil
}

func getConfig(ctx contractapi.TransactionContextInterface) (Config, error) {
	var cfg Config
	b, err := ctx.GetStub().GetState("config")
	if err != nil || b == nil {
		return cfg, fmt.Errorf("not bootstrapped")
	}
	return cfg, json.Unmarshal(b, &cfg)
}

// ---------------------------------------------------------------- anchoring (V0-V4)

type signedEntry struct {
	e   model.Entry
	h   string
	pos int
}

// AnchorBatch applies V0-V4 to a gateway batch and returns the events it recorded.
func (c *Contract) AnchorBatch(ctx contractapi.TransactionContextInterface, batchJSON string) (string, error) {
	if _, err := require(ctx, "gateway"); err != nil {
		return "", err
	}
	cfg, err := getConfig(ctx)
	if err != nil {
		return "", err
	}
	tau, err := txTime(ctx, cfg)
	if err != nil {
		return "", err
	}
	var b model.Batch
	if err := json.Unmarshal([]byte(batchJSON), &b); err != nil {
		return "", err
	}
	g, err := getGW(ctx, b.Pg)
	if err != nil {
		return "", err
	}
	if g.Mode.Name == "ha" {
		return "", fmt.Errorf("gateway is in ha mode")
	}
	pubRaw, _ := base64.StdEncoding.DecodeString(g.Pub)
	pub := ed25519.PublicKey(pubRaw)
	tx := ctx.GetStub().GetTxID()
	var ev []model.Event
	add := func(e model.Event) { e.Pg, e.Tx = b.Pg, tx; ev = append(ev, e) }
	upper := tau + (2*cfg.EpsSec+cfg.DeltaSec)*1e9

	// (V0) header
	// The signed header travels with the last sub-batch of a synchronization; intermediate
	// sub-batches carry none. Stripping it only delays truncation detection to the next sync.
	hasHeader := g.Mode.Sig && g.Mode.Seq && b.Header != nil
	if hasHeader {
		if !model.Verify(pub, model.HeaderBytes(b.Pg, b.Header.K, b.Header.Hk), b.Header.Sig) || b.Header.K < g.A {
			add(model.Event{Type: "headerreject"})
			return finish(ctx, b.Pg, g, ev)
		}
	}

	// (V1) signatures
	var ok []signedEntry
	for i, e := range b.Entries {
		h := model.EntryHash(b.Pg, e)
		if g.Mode.Sig && !model.Verify(pub, []byte(h), e.Sig) {
			add(model.Event{Type: "reject", Seq: e.Seq, H: h})
			continue
		}
		ok = append(ok, signedEntry{e: e, h: h, pos: i})
	}

	if !g.Mode.Seq {
		return anchorNoSeq(ctx, b.Pg, g, ok, tau, upper, add, &ev)
	}

	// reorder detection, then sort by sequence number
	for i := 1; i < len(ok); i++ {
		if ok[i].e.Seq < ok[i-1].e.Seq {
			add(model.Event{Type: "reorder"})
			break
		}
	}
	sort.SliceStable(ok, func(i, j int) bool { return ok[i].e.Seq < ok[j].e.Seq })

	i, hi, ti := g.A, g.Ha, g.Tlast
	seen := map[int64]string{}
	for _, s := range ok {
		e := s.e
		if e.Seq <= g.A { // already anchored earlier
			old, _ := getItem(ctx, b.Pg, seqID(e.Seq))
			if old != nil && old.H == s.h {
				add(model.Event{Type: "duplicate", Seq: e.Seq, H: s.h})
			} else {
				add(model.Event{Type: "conflict", Seq: e.Seq, H: s.h})
			}
			continue
		}
		if prev, dup := seen[e.Seq]; dup { // twice in this batch
			if prev == s.h {
				add(model.Event{Type: "duplicate", Seq: e.Seq, H: s.h})
			} else {
				add(model.Event{Type: "conflict", Seq: e.Seq, H: s.h})
			}
			continue
		}
		seen[e.Seq] = s.h
		// (V2) linkage and (V3) order
		if e.Seq != i+1 {
			add(model.Event{Type: "gap", From: i + 1, To: e.Seq - 1})
		} else if g.Mode.Chain && e.Prev != hi {
			add(model.Event{Type: "linkbreak", Seq: e.Seq})
		}
		// (V4) time
		tf := e.T < ti || e.T > upper
		if tf {
			add(model.Event{Type: "timeflag", Seq: e.Seq})
		}
		it := Item{Seq: e.Seq, H: s.h, D: e.D, T: e.T, TimeFlag: tf, Tx: tx, Custodian: g.U0}
		if err := putItem(ctx, b.Pg, seqID(e.Seq), it); err != nil {
			return "", err
		}
		g.NAccept++
		i, hi, ti = e.Seq, s.h, e.T
	}
	if hasHeader {
		if i < b.Header.K {
			add(model.Event{Type: "gap", From: i + 1, To: b.Header.K})
		} else if i == b.Header.K && hi != b.Header.Hk {
			add(model.Event{Type: "conflict", Seq: i, H: hi})
		}
		if b.Header.K > i { // signed head: later entries link to h_k
			i, hi = b.Header.K, b.Header.Hk
		}
	}
	g.A, g.Ha, g.Tlast = i, hi, ti
	return finish(ctx, b.Pg, g, ev)
}

// anchorNoSeq handles the OFCC-noSeq ablation: no sequence numbers and no header.
// Items are keyed by their hash; order comes only from the hash chain.
func anchorNoSeq(ctx contractapi.TransactionContextInterface, pg string, g *Gateway, ok []signedEntry, tau, upper int64,
	add func(model.Event), ev *[]model.Event) (string, error) {
	hi, ti := g.Ha, g.Tlast
	for _, s := range ok {
		e := s.e
		if old, _ := getItem(ctx, pg, s.h); old != nil {
			add(model.Event{Type: "duplicate", H: s.h})
			continue
		}
		if g.Mode.Chain && e.Prev != hi {
			add(model.Event{Type: "linkbreak", H: s.h})
		}
		tf := e.T < ti || e.T > upper
		if tf {
			add(model.Event{Type: "timeflag", H: s.h})
		}
		g.NAccept++
		if err := putItem(ctx, pg, s.h, Item{Seq: g.NAccept, H: s.h, D: e.D, T: e.T, TimeFlag: tf,
			Tx: ctx.GetStub().GetTxID(), Custodian: g.U0}); err != nil {
			return "", err
		}
		hi, ti = s.h, e.T
	}
	g.Ha, g.Tlast = hi, ti
	_ = tau
	return finish(ctx, pg, g, *ev)
}

func finish(ctx contractapi.TransactionContextInterface, pg string, g *Gateway, ev []model.Event) (string, error) {
	gb, _ := json.Marshal(g)
	if err := ctx.GetStub().PutState("gw:"+pg, gb); err != nil {
		return "", err
	}
	if err := putEvents(ctx, pg, ev); err != nil {
		return "", err
	}
	if ev == nil {
		ev = []model.Event{}
	}
	out, _ := json.Marshal(ev)
	return string(out), nil
}

// AnchorDigests is the hash-archive (HA) baseline: one digest per item id, duplicates reported.
func (c *Contract) AnchorDigests(ctx contractapi.TransactionContextInterface, batchJSON string) (string, error) {
	if _, err := require(ctx, "gateway"); err != nil {
		return "", err
	}
	var b model.DigestBatch
	if err := json.Unmarshal([]byte(batchJSON), &b); err != nil {
		return "", err
	}
	g, err := getGW(ctx, b.Pg)
	if err != nil {
		return "", err
	}
	if g.Mode.Name != "ha" {
		return "", fmt.Errorf("gateway not in ha mode")
	}
	tx := ctx.GetStub().GetTxID()
	var ev []model.Event
	for _, it := range b.Items {
		old, _ := getItem(ctx, b.Pg, it.ID)
		if old != nil {
			t := "conflict"
			if old.D == it.D {
				t = "duplicate"
			}
			ev = append(ev, model.Event{Type: t, Pg: b.Pg, ID: it.ID, Tx: tx})
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimLeft(it.ID, "0"), 10, 64)
		if err := putItem(ctx, b.Pg, it.ID, Item{Seq: n, D: it.D, Tx: tx, Custodian: g.U0}); err != nil {
			return "", err
		}
		g.NAccept++
	}
	return finish(ctx, b.Pg, g, ev)
}

// ---------------------------------------------------------------- custody

// TransferCustody moves custody of item id from the caller (current custodian) to another identity.
func (c *Contract) TransferCustody(ctx contractapi.TransactionContextInterface, pg string, id string, to string) error {
	cn, err := require(ctx, "collector", "investigator")
	if err != nil {
		return err
	}
	toRole, _ := ctx.GetStub().GetState("role:" + to)
	if r := string(toRole); r != "collector" && r != "investigator" {
		return fmt.Errorf("recipient %s may not hold custody", to)
	}
	it, err := getItem(ctx, pg, id)
	if err != nil || it == nil {
		return fmt.Errorf("unknown item")
	}
	if it.Custodian != cn {
		return fmt.Errorf("caller is not the current custodian")
	}
	ts, _ := ctx.GetStub().GetTxTimestamp()
	it.Transfers = append(it.Transfers, Transfer{From: cn, To: to, Ts: ts.AsTime().UnixNano()})
	it.Custodian = to
	return putItem(ctx, pg, id, *it)
}

// ---------------------------------------------------------------- queries (all roles)

func (c *Contract) GetGateway(ctx contractapi.TransactionContextInterface, pg string) (string, error) {
	if _, err := require(ctx, "gateway", "collector", "investigator", "auditor"); err != nil {
		return "", err
	}
	b, err := ctx.GetStub().GetState("gw:" + pg)
	return string(b), err
}

func rangeJSON(ctx contractapi.TransactionContextInterface, prefix, pg string) (string, error) {
	it, err := ctx.GetStub().GetStateByPartialCompositeKey(prefix, []string{pg})
	if err != nil {
		return "", err
	}
	defer it.Close()
	var parts []string
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return "", err
		}
		parts = append(parts, string(kv.Value))
	}
	return "[" + strings.Join(parts, ",") + "]", nil
}

func (c *Contract) GetItems(ctx contractapi.TransactionContextInterface, pg string) (string, error) {
	if _, err := require(ctx, "collector", "investigator", "auditor"); err != nil {
		return "", err
	}
	return rangeJSON(ctx, "item", pg)
}

func (c *Contract) GetEvents(ctx contractapi.TransactionContextInterface, pg string) (string, error) {
	if _, err := require(ctx, "collector", "investigator", "auditor"); err != nil {
		return "", err
	}
	return rangeJSON(ctx, "evt", pg)
}

func main() {
	cc, err := contractapi.NewChaincode(&Contract{})
	if err != nil {
		panic(err)
	}
	if err := cc.Start(); err != nil {
		panic(err)
	}
}
