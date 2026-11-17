#!/usr/bin/env python3
"""Build LaTeX tables and numbers.json from raw test results (stdlib only).

Usage: make_tables.py <raw_dir> <out_dir>
Writes: table_detection.tex, table_cost.tex, numbers.json (every value the paper may cite).
"""
import glob, json, math, os, statistics as st, sys
from collections import defaultdict

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447}
OPS = ["modEntry", "modPayload", "delete", "truncate", "insert", "reorder", "replay"]
OPHDR = ["ME", "MP", "Del", "Tr", "Ins", "Ro", "Rp"]
ROWS = [("ofcc", "adaptive", "OFCC"), ("ofcc", "naive", "OFCC"), ("noChain", "adaptive", "noChain"),
        ("noSig", "adaptive", "noSig"), ("noSeq", "adaptive", "noSeq"), ("noProt", "adaptive", "noProt"),
        ("noEnc", "adaptive", "noEnc"), ("ha", "adaptive", "HA"), ("ha", "naive", "HA"),
        ("cl", "adaptive", "CL"), ("cl", "naive", "CL")]
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
    e1[(d["system"], d["adversary"])][d["seed"]] = d
for (s, a), seeds in e1.items():
    key = f"e1.{s}.{a}"
    N[key + ".seeds"] = sorted(seeds)
    N[key + ".items_mean"] = st.mean(d["items"] for d in seeds.values())
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
    for name, fn in (("fa_rate", lambda d: d["false_alarm_items"] / d["untouched_items"]),
                     ("completeness", lambda d: d["complete_untouched_items"] / d["untouched_items"]),
                     ("link_mb_per_1k", lambda d: d["link_bytes"] / 2**20 / (d["items"] / 1000)),
                     ("ledger_mb_per_1k", lambda d: d["storage_bytes"].get("ledger_blocks_all_peers", 0) / 2**20 / (d["items"] / 1000)),
                     ("offchain_mb_per_1k", lambda d: d["storage_bytes"].get("offchain", 0) / 2**20 / (d["items"] / 1000)),
                     ("cldb_mb_per_1k", lambda d: d["storage_bytes"].get("cl_db", 0) / 2**20 / (d["items"] / 1000)),
                     ("cpu_s_per_1k", lambda d: sum(d["cpu_seconds"].values()) / (d["items"] / 1000)),
                     ("transfers_ok", lambda d: d["transfers_ok"]), ("transfer_errors", lambda d: d["transfer_errors"])):
        v = [fn(d) for d in seeds.values()]
        m, sd = ms(v)
        N[f"{key}.{name}"] = {"mean": m, "std": sd, "per_seed": {str(k): fn(d) for k, d in seeds.items()}}

def pct(x):
    return "--" if x is None else f"{100 * x:.0f}"

def cell(entry):
    if entry is None:
        return "--"
    m, sd = entry["mean"], entry["std"]
    return pct(m) if sd < 1e-9 else f"{100*m:.0f}$\\pm${100*sd:.0f}"

lines = [r"\begin{tabular}{@{}llrrrrrrrrrr@{}}", r"\toprule",
         r" & & \multicolumn{7}{c}{Before upload} & After & FA & Compl. \\ \cmidrule(lr){3-9}",
         "System & Adv. & " + " & ".join(OPHDR) + r" & upload & (\%) & (\%) \\", r"\midrule"]
for s, a, lab in ROWS:
    if (s, a) not in e1:
        continue
    k = f"e1.{s}.{a}"
    row = [lab, "A" if a == "adaptive" else "N"] + [cell(N[f"{k}.det.pre.{op}"]) for op in OPS]
    row += [cell(N[f"{k}.det.post.all"]),
            f"{100*N[k+'.fa_rate']['mean']:.1f}", f"{100*N[k+'.completeness']['mean']:.1f}"]
    lines.append(" & ".join(row) + r" \\")
    if s in ("noEnc", "cl") and a == "adaptive" and s == "noEnc":
        lines.append(r"\midrule")
lines += [r"\bottomrule", r"\end{tabular}"]
open(os.path.join(out, "table_detection.tex"), "w").write("\n".join(lines) + "\n")

cost = [r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
        r"System & Link (MB) & Ledger (MB) & Off-chain or DB (MB) & CPU (s) \\", r"\midrule"]
for s, lab in (("ofcc", "OFCC"), ("noEnc", "OFCC-noEnc"), ("ha", "HA"), ("cl", "CL")):
    k = f"e1.{s}.adaptive"
    if k + ".link_mb_per_1k" not in N:
        continue
    f2 = lambda e: f"{e['mean']:.1f}$\\pm${e['std']:.1f}"
    store = N[k + (".cldb_mb_per_1k" if s == "cl" else ".offchain_mb_per_1k")]
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
for s in ("ha", "cl"):
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

# ---------------- clock
for f in glob.glob(os.path.join(raw, "**", "eclock_*.json"), recursive=True):
    d = json.load(open(f))
    for r in d["rows"]:
        N.setdefault(f"clock.{r['gateway']}.flag_rate", {})[str(d["seed"])] = r["time_flagged"] / r["items"]
for k in [k for k in N if k.startswith("clock.")]:
    if "mean" not in N[k]:
        m, sd = ms(list(N[k].values()))
        N[k] = {"mean": m, "std": sd, "per_seed": N[k]}

json.dump(N, open(os.path.join(out, "numbers.json"), "w"), indent=1, sort_keys=True, default=str)
print("wrote tables and", len(N), "numbers to", out)
