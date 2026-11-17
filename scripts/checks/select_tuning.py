#!/usr/bin/env python3
"""Apply the pre-registered tuning rule to validation-seed results (stdlib only).

Objective: minimize mean sync time after a 10-minute outage, subject to mean item-level p95
latency <= 2.0 s at 100 items/s. Ties: lower p95. Usage: select_tuning.py <tune_raw_dir> <out.json>
"""
import glob, json, os, statistics as st, sys
from collections import defaultdict

raw, out = sys.argv[1], sys.argv[2]
sync, p95 = defaultdict(list), defaultdict(list)
for f in glob.glob(os.path.join(raw, "**", "*.json"), recursive=True):
    d = json.load(open(f))
    if d.get("seed") not in (801, 802):
        continue  # validation seeds only
    key = (d["config"]["batch_timeout"], d["config"]["b"])
    if d["exp"] == "e2":
        sync[key] += [r["sync_seconds"] for r in d["rows"] if r["outage_min"] == 10]
    elif d["exp"] == "e3":
        p95[key] += [r["item_latency_p95_s"] for r in d["rows"] if r["offered_items_per_s"] == 100]
rows = []
for key in sorted(set(sync) | set(p95)):
    s = st.mean(sync[key]) if sync[key] else None
    p = st.mean(p95[key]) if p95[key] else None
    rows.append({"batch_timeout": key[0], "b": key[1], "sync10_s": s, "item_p95_s": p,
                 "n_sync": len(sync[key]), "n_p95": len(p95[key]),
                 "feasible": p is not None and p <= 2.0})
feas = [r for r in rows if r["feasible"] and r["sync10_s"] is not None]
best = min(feas, key=lambda r: (r["sync10_s"], r["item_p95_s"])) if feas else None
print(f"{'BT':>5} {'b':>4} {'sync10(s)':>10} {'p95(s)':>8} feasible")
for r in rows:
    print(f"{r['batch_timeout']:>5} {r['b']:>4} {r['sync10_s'] or float('nan'):10.2f} {r['item_p95_s'] or float('nan'):8.3f} {r['feasible']}")
print("SELECTED:", best)
os.makedirs(os.path.dirname(out), exist_ok=True)
json.dump({"rule": "min sync time after 10-min outage s.t. item p95 <= 2.0 s at 100 items/s; validation seeds 801-802",
           "grid": rows, "selected": best}, open(out, "w"), indent=1)
