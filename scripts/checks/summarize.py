#!/usr/bin/env python3
"""Summarize raw experiment JSON files (stdlib only).

Usage: summarize.py <raw_dir> [--json out.json]
Prints per-system tables for E1 (detection, false alarms, completeness, cost), E2 (sync time) and
E3 (throughput, latency). With several seeds: mean ± std and paired differences
(OFCC minus other system, positive = OFCC higher) with a 95% t-interval.
"""
import glob, json, math, os, sys, statistics as st
from collections import defaultdict

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228}
OPS = ["modEntry", "modPayload", "delete", "truncate", "insert", "reorder", "replay"]


def ms(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None, None
    return st.mean(xs), (st.stdev(xs) if len(xs) > 1 else 0.0)


def paired(a, b):
    """a, b: dict seed -> value. Returns mean diff, half-width, df (or None)."""
    seeds = sorted(set(a) & set(b))
    d = [a[s] - b[s] for s in seeds]
    if len(d) < 2:
        return (d[0] if d else None), None, len(d) - 1
    m, s = st.mean(d), st.stdev(d)
    df = len(d) - 1
    return m, T95.get(df, 1.96) * s / math.sqrt(len(d)), df


def e1(raw):
    rows = defaultdict(dict)  # (system, adversary) -> seed -> metrics
    for f in sorted(glob.glob(os.path.join(raw, "e1_*.json"))):
        d = json.load(open(f))
        det = {}
        for pos in ("pre", "post"):
            for op in OPS:
                ops = [o for o in d["ops"] if o["pos"] == pos and o["type"] == op and not o.get("na")]
                det[(pos, op)] = (sum(o["detected"] for o in ops) / len(ops)) if ops else None
        allpre = [o for o in d["ops"] if o["pos"] == "pre" and not o.get("na")]
        allpost = [o for o in d["ops"] if o["pos"] == "post" and not o.get("na")]
        k = d["items"] / 1000.0
        cpu = d["cpu_seconds"]
        rows[(d["system"], d["adversary"])][d["seed"]] = {
            "det": det,
            "det_pre_all": sum(o["detected"] for o in allpre) / len(allpre) if allpre else None,
            "det_post_all": sum(o["detected"] for o in allpost) / len(allpost) if allpost else None,
            "fa_item_rate": d["false_alarm_items"] / d["untouched_items"],
            "fa_rounds": d["clean_rounds_with_alert"], "clean_rounds": d["clean_rounds"],
            "completeness": d["complete_untouched_items"] / d["untouched_items"],
            "items": d["items"], "transfers_ok": d["transfers_ok"], "transfer_errors": d["transfer_errors"],
            "link_kb_per_1k": d["link_bytes"] / 1024 / k,
            "ledger_kb_per_1k": (d["storage_bytes"].get("ledger_blocks_all_peers") or d["storage_bytes"].get("ledger_all_peers", 0)) / 1024 / k,
            "offchain_kb_per_1k": d["storage_bytes"].get("offchain", 0) / 1024 / k,
            "cl_db_kb_per_1k": d["storage_bytes"].get("cl_db", 0) / 1024 / k,
            "cpu_s_per_1k": sum(v for v in cpu.values()) / k,
            "cpu_fabric_s_per_1k": cpu.get("fabric", 0) / k,
            "wall_s": d["wall_seconds"],
        }
    return rows


def show_e1(rows):
    print("\n=== E1: detection rate per operation (pre-upload | post-upload), mean over seeds ===")
    hdr = "system      adv       " + " ".join(f"{o[:6]:>7s}" for o in OPS)
    for pos in ("pre", "post"):
        print(f"--- {pos}-upload ---")
        print(hdr)
        for (sysn, adv), seeds in sorted(rows.items()):
            cells = []
            for op in OPS:
                m, _ = ms([v["det"][(pos, op)] for v in seeds.values()])
                cells.append("     NA" if m is None else f"{m:7.2f}")
            print(f"{sysn:11s} {adv:9s} " + " ".join(cells))
    print("\n=== E1: overall, false alarms, completeness, cost (per 1,000 items) ===")
    keys = ["det_pre_all", "det_post_all", "fa_item_rate", "completeness", "link_kb_per_1k", "ledger_kb_per_1k",
            "offchain_kb_per_1k", "cl_db_kb_per_1k", "cpu_s_per_1k", "wall_s"]
    print("system      adv       n " + " ".join(f"{k[:14]:>15s}" for k in keys))
    for (sysn, adv), seeds in sorted(rows.items()):
        cells = []
        for kk in keys:
            m, s = ms([v[kk] for v in seeds.values()])
            cells.append(f"{'NA':>15s}" if m is None else (f"{m:9.3f}±{s:5.3f}" if len(seeds) > 1 else f"{m:15.3f}"))
        print(f"{sysn:11s} {adv:9s} {len(seeds)} " + " ".join(cells))
    errs = {k: sum(v["transfer_errors"] for v in s.values()) for k, s in rows.items()}
    print("transfer errors:", {f"{a}/{b}": e for (a, b), e in errs.items() if e})


def e2(raw):
    out = defaultdict(lambda: defaultdict(dict))  # system -> D -> seed -> sync seconds
    for f in sorted(glob.glob(os.path.join(raw, "e2_*.json"))):
        d = json.load(open(f))
        for r in d["rows"]:
            out[d["system"]][r["outage_min"]][d["seed"]] = r["sync_seconds"]
    print("\n=== E2: synchronization time after an outage (s), 8 gateways, 1 item/s each ===")
    Ds = sorted({D for s in out.values() for D in s})
    print("system " + " ".join(f"{'D=' + str(D) + 'min':>16s}" for D in Ds))
    for s, byD in sorted(out.items()):
        cells = []
        for D in Ds:
            m, sd = ms(list(byD[D].values()))
            cells.append(f"{'':>16s}" if m is None else f"{m:9.2f}±{sd:5.2f}")
        print(f"{s:6s} " + " ".join(cells))
    return out


def e3(raw):
    out = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))  # (system, orgs) -> L -> metric -> seed -> v
    for f in sorted(glob.glob(os.path.join(raw, "e3_*.json"))):
        d = json.load(open(f))
        for r in d["rows"]:
            for k in ("throughput_items_per_s", "latency_mean_s", "latency_p50_s", "latency_p95_s", "errors"):
                out[(d["system"], d["config"]["orgs"])][r["offered_items_per_s"]][k][d["seed"]] = r[k]
    print("\n=== E3: throughput (items/s) and latency (s) at fixed offered loads ===")
    for (s, orgs), byL in sorted(out.items()):
        for L, m in sorted(byL.items()):
            thr, _ = ms(list(m["throughput_items_per_s"].values()))
            p50, _ = ms(list(m["latency_p50_s"].values()))
            p95, _ = ms(list(m["latency_p95_s"].values()))
            mean, _ = ms(list(m["latency_mean_s"].values()))
            er = sum(m["errors"].values())
            print(f"{s:5s} orgs={orgs} L={L:4d}  thr={thr:7.1f}  mean={mean:6.3f}  p50={p50:6.3f}  p95={p95:6.3f}  errors={er}")
    return out


if __name__ == "__main__":
    raw = sys.argv[1]
    r1 = e1(raw)
    if r1:
        show_e1(r1)
        base = r1.get(("ofcc", "adaptive"), {})
        if len(base) > 1:
            print("\n=== Paired differences, OFCC minus other (adaptive), 95% t-interval ===")
            for (sysn, adv), seeds in sorted(r1.items()):
                if adv != "adaptive" or sysn == "ofcc":
                    continue
                for kk in ("det_pre_all", "completeness", "cpu_s_per_1k", "link_kb_per_1k"):
                    m, hw, df = paired({k: v[kk] for k, v in base.items()}, {k: v[kk] for k, v in seeds.items()})
                    if m is not None:
                        print(f"  vs {sysn:8s} {kk:16s} {m:+9.3f}" + (f" ± {hw:.3f} (df={df})" if hw is not None else ""))
    e2(raw)
    e3(raw)
