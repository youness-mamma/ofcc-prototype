#!/usr/bin/env python3
"""Build LaTeX tables and numbers.json from raw test results (stdlib only).

Usage: make_tables.py <raw_dir> <out_dir>
Writes: table_detection.tex, table_cost.tex, numbers.json (every value the paper may cite).
"""
import glob, json, math, os, statistics as st, sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scoring import rescore

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447}
OPS = ["modEntry", "modPayload", "delete", "truncate", "insert", "reorder", "replay"]
OPHDR = ["ME", "MP", "Del", "Tr", "Ins", "Ro", r"Rp$^{*}$"]
ROWS = [("ofcc", "adaptive", "OFCC"), ("noChain", "adaptive", "noChain"),
        ("noSig", "adaptive", "noSig"), ("noSeq", "adaptive", "noSeq"), ("noProt", "adaptive", "noProt"),
        ("ha", "adaptive", "HA"), ("ha", "naive", "HA"),
        ("cls", "adaptive", "CL-S"), ("cls", "naive", "CL-S"), ("cl", "adaptive", "CL"), ("cl", "naive", "CL")]
raw, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
N = {}


def ms(v):
    v = [x for x in v if x is not None]
    if not v:
        return None, None
    return st.mean(v), (st.stdev(v) if len(v) > 1 else 0.0)


def paired(a, b):
    s = sorted(set(a) & set(b))
    d = [a[k] - b[k] for k in s]
    if len(d) < 2:
        return None
    m, sd = st.mean(d), st.stdev(d)
    return {"mean": m, "hw": T95[len(d) - 1] * sd / math.sqrt(len(d)), "df": len(d) - 1, "n": len(d)}


# ---------------- E1
e1 = defaultdict(dict)
for f in glob.glob(os.path.join(raw, "**", "e1_*.json"), recursive=True):
    d = json.load(open(f))
    d["ops"] = rescore(d)
    e1[(d["system"], d["adversary"])][d["seed"]] = d
for (s, a), seeds in e1.items():
    key = f"e1.{s}.{a}"
    N[key + ".seeds"] = sorted(seeds)
    N[key + ".items_mean"] = st.mean(d["items"] for d in seeds.values())
    N[key + ".items_mean_round100"] = round(N[key + ".items_mean"] / 100) * 100  # for "about N items"
    for pos in ("pre", "post"):
        for op in OPS:
            v = []
            for d in seeds.values():
                ops = [o for o in d["ops"] if o["pos"] == pos and o["type"] == op and not o.get("na")]
                v.append(sum(o["detected"] for o in ops) / len(ops) if ops else None)
            m, sd = ms(v)
            N[f"{key}.det.{pos}.{op}"] = None if m is None else {"mean": m, "std": sd, "n_ops_per_seed": None}
        v = []
        for d in seeds.values():
            ops = [o for o in d["ops"] if o["pos"] == pos and not o.get("na")]
            v.append(sum(o["detected"] for o in ops) / len(ops) if ops else None)
        m, sd = ms(v)
        N[f"{key}.det.{pos}.all"] = None if m is None else {"mean": m, "std": sd}
        N[f"{key}.ops.{pos}.applied_total"] = sum(sum(1 for o in d["ops"] if o["pos"] == pos and not o.get("na")) for d in seeds.values())
    # before upload, a replay surfaces only as a duplicate (not applied): reported as neutralized, not detected
    N[f"{key}.pre.detected_nonreplay_total"] = sum(sum(o["detected"] for o in d["ops"] if o["pos"] == "pre" and not o.get("na") and o["type"] != "replay") for d in seeds.values())
    N[f"{key}.pre.nonreplay_total"] = sum(sum(1 for o in d["ops"] if o["pos"] == "pre" and not o.get("na") and o["type"] != "replay") for d in seeds.values())
    N[f"{key}.pre.replay_neutralized_total"] = sum(sum(o["detected"] for o in d["ops"] if o["pos"] == "pre" and not o.get("na") and o["type"] == "replay") for d in seeds.values())
    N[f"{key}.pre.replay_total"] = sum(sum(1 for o in d["ops"] if o["pos"] == "pre" and not o.get("na") and o["type"] == "replay") for d in seeds.values())
    v = []
    for d in seeds.values():
        # item-level localisation over the non-replay operations only (replays are neutralized, not detected)
        ops = [o for o in d["ops"] if o["pos"] == "pre" and not o.get("na") and o["type"] != "replay"]
        v.append(sum(o.get("detected_item", False) for o in ops) / len(ops) if ops else None)
    m, sd = ms(v)
    N[f"{key}.det_item.pre.all"] = None if m is None else {"mean": m, "std": sd}
    for kind in ("forge", "rewrite"):
        outs = [c["outcome"] for d in seeds.values() for c in (d.get("custody_attacks") or []) if c["kind"] == kind]
        N[f"{key}.custody.{kind}"] = {"n": len(outs), "prevented": outs.count("prevented"),
                                      "detected": outs.count("detected"), "undetected": outs.count("undetected")}
    for name, fn in (("fa_rate", lambda d: d["false_alarm_items"] / d["untouched_items"]),
                     ("completeness", lambda d: d["complete_untouched_items"] / d["untouched_items"]),
                     ("link_mb_per_1k", lambda d: d["link_bytes"] / 2**20 / (d["items"] / 1000)),
                     ("ledger_mb_per_1k", lambda d: d["storage_bytes"].get("ledger_blocks_all_peers", 0) / 2**20 / (d["items"] / 1000)),
                     ("offchain_mb_per_1k", lambda d: d["storage_bytes"].get("offchain", 0) / 2**20 / (d["items"] / 1000)),
                     ("cldb_mb_per_1k", lambda d: d["storage_bytes"].get("cl_db", 0) / 2**20 / (d["items"] / 1000)),
                     ("cpu_s_per_1k", lambda d: sum(d["cpu_seconds"].values()) / (d["items"] / 1000)),
                     ("cpu_fabric_s_per_1k", lambda d: d["cpu_seconds"].get("fabric", 0) / (d["items"] / 1000)),
                     ("transfers_ok", lambda d: d["transfers_ok"]), ("transfer_errors", lambda d: d["transfer_errors"])):
        v = [fn(d) for d in seeds.values()]
        m, sd = ms(v)
        N[f"{key}.{name}"] = {"mean": m, "std": sd, "per_seed": {str(k): fn(d) for k, d in seeds.items()}}

def pct(x):
    return "--" if x is None else f"{100 * x:.0f}"

def ccell(e):
    if not e or not e["n"]:
        return "--"
    if e["prevented"] == e["n"]:
        return "P"
    return f"{100 * e['detected'] / e['n']:.0f}"

def cell(entry):
    if entry is None:
        return "--"
    m, sd = entry["mean"], entry["std"]
    return pct(m) if sd < 1e-9 else f"{100*m:.0f}$\\pm${100*sd:.0f}"

lines = [r"\begin{tabular}{@{}llrrrrrrrrrrrr@{}}", r"\toprule",
         r" & & \multicolumn{8}{c}{Before upload} & After & \multicolumn{2}{c}{Custody} & FA \\ \cmidrule(lr){3-10}\cmidrule(lr){12-13}",
         "System & Adv. & " + " & ".join(OPHDR) + r" & Item & upload & Forge & Rewr. & (\%) \\", r"\midrule"]
for s, a, lab in ROWS:
    if (s, a) not in e1:
        continue
    k = f"e1.{s}.{a}"
    row = [lab, "A" if a == "adaptive" else "N"] + [cell(N[f"{k}.det.pre.{op}"]) for op in OPS]
    row += [cell(N[f"{k}.det_item.pre.all"]), cell(N[f"{k}.det.post.all"]), ccell(N.get(f"{k}.custody.forge")), ccell(N.get(f"{k}.custody.rewrite")),
            f"{100*N[k+'.fa_rate']['mean']:.1f}"]
    lines.append(" & ".join(row) + r" \\")
    if s == "noProt":
        lines.append(r"\midrule")
lines += [r"\bottomrule", r"\end{tabular}"]
open(os.path.join(out, "table_detection.tex"), "w").write("\n".join(lines) + "\n")

cost = [r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
        r"System & Link (MB) & Ledger (MB) & Off-chain or DB (MB) & CPU (s) \\", r"\midrule"]
for s, lab in (("ofcc", "OFCC"), ("ha", "HA"), ("cls", "CL-S"), ("cl", "CL")):
    k = f"e1.{s}.adaptive"
    if k + ".link_mb_per_1k" not in N:
        continue
    f2 = lambda e: "--" if abs(e['mean']) < 1e-9 else (f"{e['mean']:.1f}$\\pm${e['std']:.1f}" if e['std'] >= 0.05 else f"{e['mean']:.1f}" + r"$\pm{<}0.1$")
    store = N[k + (".cldb_mb_per_1k" if s in ("cl", "cls") else ".offchain_mb_per_1k")]
    cost.append(" & ".join([lab, f2(N[k+".link_mb_per_1k"]), f2(N[k+".ledger_mb_per_1k"]), f2(store), f2(N[k+".cpu_s_per_1k"])]) + r" \\")
cost += [r"\bottomrule", r"\end{tabular}"]
open(os.path.join(out, "table_cost.tex"), "w").write("\n".join(cost) + "\n")

# paired differences OFCC minus other (adaptive)
base = e1.get(("ofcc", "adaptive"), {})
for (s, a), seeds in e1.items():
    if a != "adaptive" or s == "ofcc":
        continue
    for name in ("cpu_s_per_1k", "link_mb_per_1k", "ledger_mb_per_1k"):
        N[f"paired.e1.ofcc_minus_{s}.{name}"] = paired({k: v for k, v in N[f"e1.ofcc.adaptive.{name}"]["per_seed"].items()},
                                                    {k: v for k, v in N[f"e1.{s}.adaptive.{name}"]["per_seed"].items()})

# ---------------- E2
e2 = defaultdict(lambda: defaultdict(dict))
for f in glob.glob(os.path.join(raw, "**", "e2_*.json"), recursive=True):
    d = json.load(open(f))
    for r in d["rows"]:
        e2[d["system"]][r["outage_min"]][str(d["seed"])] = r["sync_seconds"]
for s, byD in e2.items():
    for D, v in byD.items():
        m, sd = ms(list(v.values()))
        N[f"e2.{s}.D{D}"] = {"mean": m, "std": sd, "per_seed": v}
# linear fit of OFCC sync time over outage length (all lengths), seconds per minute
for s in ("ofcc", "cls"):
    pts = [(D, v) for D, byS in e2.get(s, {}).items() for v in byS.values()]
    if len(pts) > 2:
        mx = st.mean(p[0] for p in pts); my = st.mean(p[1] for p in pts)
        N[f"e2.{s}.fit_s_per_min"] = sum((x - mx) * (y - my) for x, y in pts) / sum((x - mx) ** 2 for x, _ in pts)
for s in ("ha", "cl", "cls"):
    for D in e2.get("ofcc", {}):
        if D in e2.get(s, {}):
            N[f"paired.e2.ofcc_minus_{s}.D{D}"] = paired(e2["ofcc"][D], e2[s][D])

# ---------------- E3
for f in glob.glob(os.path.join(raw, "**", "e3_*.json"), recursive=True):
    d = json.load(open(f))
    tag = "scale" if "_scale" in f else "sys"
    for r in d["rows"]:
        for m in ("throughput_items_per_s", "item_latency_p50_s", "item_latency_p95_s", "item_latency_mean_s", "errors"):
            N.setdefault(f"e3.{tag}.{d['system']}.orgs{d['config']['orgs']}.L{r['offered_items_per_s']}.{m}", {})[str(d["seed"])] = r.get(m)
for k in [k for k in N if k.startswith("e3.") and isinstance(N[k], dict) and "mean" not in N[k]]:
    m, sd = ms(list(N[k].values()))
    N[k] = {"mean": m, "std": sd, "per_seed": N[k]}

# org scaling: paired throughput / p95 at each load, 3 orgs minus 5 orgs (same runner job per seed)
for L in (800, 1600):
    for m in ("throughput_items_per_s", "item_latency_p95_s"):
        a = N.get(f"e3.scale.ofcc.orgs3.L{L}.{m}", {}).get("per_seed", {})
        b = N.get(f"e3.scale.ofcc.orgs5.L{L}.{m}", {}).get("per_seed", {})
        if a and b:
            N[f"paired.e3.orgs3_minus_orgs5.L{L}.{m}"] = paired(a, b)

# systems at saturation: OFCC minus HA (same runner job per seed)
for L in (800, 1600):
    for m in ("throughput_items_per_s", "item_latency_p95_s"):
        a = N.get(f"e3.sys.ofcc.orgs4.L{L}.{m}", {}).get("per_seed", {})
        b = N.get(f"e3.sys.ha.orgs4.L{L}.{m}", {}).get("per_seed", {})
        if a and b:
            N[f"paired.e3.ofcc_minus_ha.L{L}.{m}"] = paired(a, b)

# benign link loss
for f in glob.glob(os.path.join(raw, "**", "eloss_*.json"), recursive=True):
    d = json.load(open(f))
    s = str(d["seed"])
    N.setdefault("eloss.complete_rate", {})[s] = d["complete"] / d["items"]
    N.setdefault("eloss.items", {})[s] = d["items"]
    N.setdefault("eloss.lost_syncs", {})[s] = d["lost_syncs"]
    N.setdefault("eloss.lost_acks", {})[s] = d["lost_acks"]
    k = d["alert_kinds"]
    N.setdefault("eloss.duplicates", {})[s] = k.get("duplicate", 0)
    N.setdefault("eloss.non_duplicate_alerts", {})[s] = sum(v for kk, v in k.items() if kk != "duplicate")
for k in [k for k in N if k.startswith("eloss.")]:
    if "mean" not in N[k]:
        m, sd = ms(list(N[k].values()))
        N[k] = {"mean": m, "std": sd, "per_seed": N[k], "sum": sum(N[k].values())}

# ---------------- clock
for f in glob.glob(os.path.join(raw, "**", "eclock_*.json"), recursive=True):
    d = json.load(open(f))
    for r in d["rows"]:
        N.setdefault(f"clock.{r['gateway']}.flag_rate", {})[str(d["seed"])] = r["time_flagged"] / r["items"]
for k in [k for k in N if k.startswith("clock.")]:
    if "mean" not in N[k]:
        m, sd = ms(list(N[k].values()))
        N[k] = {"mean": m, "std": sd, "per_seed": N[k]}

# ---------------- derived quantities cited in the text
# exact two-sided 95% Clopper-Pearson lower bound for n successes out of n
for n in (100,):
    N[f"derived.cp_lower_{n}_of_{n}"] = 0.025 ** (1 / n)
# link volume after the 20-minute outage (9,600 items) and its transfer time at an assumed 4 Mbit/s satellite link
mb = N["e1.ofcc.adaptive.link_mb_per_1k"]["mean"] * 9.6
N["derived.link_mb_D20"] = mb
N["derived.link_minutes_D20_at_4mbit"] = mb * 2**20 * 8 / 4e6 / 60
N["derived.link_seconds_D20_at_100mbit"] = mb * 2**20 * 8 / 100e6  # LEO-class link, sensitivity
# ---- catch-up after outages (E2 raw rows, OFCC). A gateway submits its batches one at a time, each waiting
# for commit; eight gateways sync in parallel. s per batch per gateway = sync_seconds / (txs / 8).
spb, p50, p95 = [], [], []
items_by_D = {}
for f in glob.glob(os.path.join(raw, "**", "e2_ofcc*.json"), recursive=True):
    d = json.load(open(f))
    for r in d["rows"]:
        spb.append(r["sync_seconds"] / (r["txs"] / 8))
        p50.append(r["tx_latency_p50"])
        p95.append(r["tx_latency_p95"])
        items_by_D[r["outage_min"]] = r["items"]
if spb:
    N["derived.catchup_s_per_batch_per_gw"] = st.mean(spb)
    N["derived.catchup_tx_latency_p50_min"] = min(p50)
    N["derived.catchup_tx_latency_p50_max"] = max(p50)
    N["derived.catchup_tx_latency_p95_max"] = max(p95)
    # sequential ceiling: 8 gateways x b=100 items per commit round trip
    N["derived.catchup_ceiling_items_per_s"] = 8 * 100 / st.mean(spb)
if 360 in items_by_D:
    gib = N["e1.ofcc.adaptive.link_mb_per_1k"]["mean"] * items_by_D[360] / 1000 / 1024
    N["derived.backlog_6h_gib"] = gib
    N["derived.backlog_6h_seconds_at_100mbit"] = gib * 2**30 * 8 / 100e6
    # ten vessels after six hours, bounded below by the highest measured committed throughput (1,600 items/s point)
    thr = N["e3.sys.ofcc.orgs4.L1600.throughput_items_per_s"]["mean"]
    N["derived.catchup_10_vessels_6h_items"] = 10 * items_by_D[360]
    N["derived.catchup_10_vessels_6h_minutes_at_max_thr"] = 10 * items_by_D[360] / thr / 60
# vessel equivalents at 8 items/s per vessel: latency starts rising above 400 items/s; max committed throughput
N["derived.vessels_at_400"] = 400 / 8
N["derived.vessels_at_max_thr"] = N["e3.sys.ofcc.orgs4.L1600.throughput_items_per_s"]["mean"] / 8

json.dump(N, open(os.path.join(out, "numbers.json"), "w"), indent=1, sort_keys=True, default=str)
print("wrote tables and", len(N), "numbers to", out)
