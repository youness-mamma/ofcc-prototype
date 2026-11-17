#!/usr/bin/env python3
"""Fig. 2: (a) sync time vs outage length, (b) throughput vs offered load, (c) item p95 latency vs load.
Reads raw JSON (E2, E3) and writes a vector PDF + 1200-dpi PNG.
Usage: make_results_figure.py <raw_dir> <out_stem>
"""
import glob, json, os, statistics as st, sys
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

matplotlib.rcParams.update({"pdf.fonttype": 42, "ps.fonttype": 42, "font.size": 7, "axes.titlesize": 7,
                            "axes.labelsize": 7, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5, "legend.fontsize": 6.5,
                            "font.family": "DejaVu Sans", "axes.linewidth": 0.6, "lines.linewidth": 1.1})
# one dark, grayscale-distinct colour + marker + line style per system, fixed across all figures
STY = {"ofcc": dict(color="#1b3a5c", marker="o", ls="-", label="OFCC"),
       "ha": dict(color="#7a4a1e", marker="s", ls="--", label="HA"),
       "cl": dict(color="#4d4d4d", marker="^", ls=":", label="CL"),
       3: dict(color="#1b3a5c", marker="v", ls="-.", label="OFCC, 3 orgs"),
       4: dict(color="#1b3a5c", marker="o", ls="-", label="OFCC, 4 orgs"),
       5: dict(color="#1b3a5c", marker="D", ls=(0, (1, 1)), label="OFCC, 5 orgs")}

raw, stem = sys.argv[1], sys.argv[2]
e2 = defaultdict(lambda: defaultdict(list))
e3 = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
for f in glob.glob(os.path.join(raw, "**", "*.json"), recursive=True):
    d = json.load(open(f))
    if d.get("exp") == "e2":
        for r in d["rows"]:
            e2[d["system"]][r["outage_min"]].append(r["sync_seconds"])
    if d.get("exp") == "e3":
        key = d["system"] if "_scale" not in f else d["config"]["orgs"]
        for r in d["rows"]:
            e3[key][r["offered_items_per_s"]]["thr"].append(r["throughput_items_per_s"])
            e3[key][r["offered_items_per_s"]]["p95"].append(r.get("item_latency_p95_s", r["latency_p95_s"]))

def mstd(v):
    return st.mean(v), (st.stdev(v) if len(v) > 1 else 0.0)

fig, ax = plt.subplots(1, 3, figsize=(4.8, 1.75), constrained_layout=True)
for s in ("ofcc", "ha", "cl"):
    if s in e2:
        xs = sorted(e2[s]); m = [mstd(e2[s][x]) for x in xs]
        ax[0].errorbar(xs, [a for a, _ in m], yerr=[b for _, b in m], capsize=1.5, ms=3, **STY[s])
ax[0].set_xlabel("Outage length (min)"); ax[0].set_ylabel("Sync time (s)"); ax[0].set_title("(a) Synchronization")
for k in ("ofcc", "ha", "cl", 3, 5):
    if k not in e3:
        continue
    xs = sorted(e3[k])
    for i, met in ((1, "thr"), (2, "p95")):
        m = [mstd(e3[k][x][met]) for x in xs]
        ax[i].errorbar(xs, [a for a, _ in m], yerr=[b for _, b in m], capsize=1.5, ms=3, **STY[k])
lim = [50, 1700]
ax[1].plot(lim, lim, color="#b0b0b0", lw=0.6, ls="-", zorder=0)
ax[1].set_xscale("log"); ax[1].set_yscale("log"); ax[2].set_xscale("log"); ax[2].set_yscale("log")
ax[1].set_xlabel("Offered load (items/s)"); ax[1].set_ylabel("Throughput (items/s)"); ax[1].set_title("(b) Throughput")
ax[2].set_xlabel("Offered load (items/s)"); ax[2].set_ylabel("Item p95 latency (s)"); ax[2].set_title("(c) Latency")
from matplotlib.ticker import FixedLocator, FuncFormatter, NullLocator
plain = FuncFormatter(lambda v, _: f"{v:g}")
loads = [50, 100, 200, 400, 800, 1600]
for a in (ax[1], ax[2]):
    a.xaxis.set_major_locator(FixedLocator(loads)); a.xaxis.set_major_formatter(plain); a.xaxis.set_minor_locator(NullLocator())
    a.tick_params(axis="x", labelrotation=45)
ax[1].yaxis.set_major_locator(FixedLocator(loads)); ax[1].yaxis.set_major_formatter(plain); ax[1].yaxis.set_minor_locator(NullLocator())
ax[2].yaxis.set_major_locator(FixedLocator([0.1, 0.2, 0.5, 1, 2, 5, 10])); ax[2].yaxis.set_major_formatter(plain)
ax[2].yaxis.set_minor_locator(NullLocator())
for a in ax:
    a.grid(True, lw=0.3, color="#dddddd"); a.set_axisbelow(True)
h, l = [], []
for a in ax:
    for hh, ll in zip(*a.get_legend_handles_labels()):
        if ll not in l:
            h.append(hh); l.append(ll)
fig.legend(h, l, loc="outside lower center", ncol=5, frameon=False, handlelength=2.2, columnspacing=1.0)
fig.savefig(stem + ".pdf"); fig.savefig(stem + ".png", dpi=1200)
print("wrote", stem + ".pdf")
