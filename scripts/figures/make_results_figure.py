#!/usr/bin/env python3
"""Fig. 3 (figure03): (a) sync time vs outage length; (b) item p95 latency vs offered load (OFCC, HA, CL, CL-S; 4 orgs);
(c) OFCC item p95 latency vs load for 3, 4, 5 organizations. Markers: mean over seeds; bars: min-max.
Usage: make_results_figure.py <raw_dir> <out_stem>  -> <out_stem>.pdf (vector) and .png (1200 dpi)
"""
import glob, json, os, statistics as st, sys
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, FuncFormatter, NullLocator

matplotlib.rcParams.update({"pdf.fonttype": 42, "ps.fonttype": 42, "font.size": 7, "axes.titlesize": 7,
                            "axes.labelsize": 7, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5, "legend.fontsize": 6.5,
                            "font.family": "DejaVu Sans", "axes.linewidth": 0.6, "lines.linewidth": 1.1})
STY = {"ofcc": dict(color="#1b3a5c", marker="o", ls="-", label="OFCC"),
       "ha": dict(color="#7a4a1e", marker="s", ls="--", label="HA"),
       "cl": dict(color="#4d4d4d", marker="^", ls=":", label="CL"),
       "cls": dict(color="#8c8c8c", marker="x", ls="-.", label="CL-S", mfc="none"),
       3: dict(color="#1b3a5c", marker="v", ls="--", label="3 orgs"),
       4: dict(color="#1b3a5c", marker="o", ls="-", label="4 orgs"),
       5: dict(color="#1b3a5c", marker="D", ls=":", label="5 orgs")}

raw, stem = sys.argv[1], sys.argv[2]
e2 = defaultdict(lambda: defaultdict(list))
sysl = defaultdict(lambda: defaultdict(list))   # systems comparison (E3 job, 4 orgs)
scal = defaultdict(lambda: defaultdict(list))   # org scaling job
for f in glob.glob(os.path.join(raw, "**", "*.json"), recursive=True):
    d = json.load(open(f))
    if d.get("exp") == "e2":
        for r in d["rows"]:
            e2[d["system"]][r["outage_min"]].append(r["sync_seconds"])
    if d.get("exp") == "e3":
        tgt = scal[d["config"]["orgs"]] if "_scale" in os.path.basename(f) else sysl[d["system"]]
        for r in d["rows"]:
            tgt[r["offered_items_per_s"]].append(r["item_latency_p95_s"])

def plot(ax, series, key):
    xs = sorted(series)
    m = [st.mean(series[x]) for x in xs]
    lo = [m[i] - min(series[x]) for i, x in enumerate(xs)]
    hi = [max(series[x]) - m[i] for i, x in enumerate(xs)]
    ax.errorbar(xs, m, yerr=[lo, hi], capsize=1.5, ms=3, elinewidth=0.6, **STY[key])

fig, ax = plt.subplots(1, 3, figsize=(4.8, 1.9), constrained_layout=True)
for s in ("ofcc", "ha", "cl", "cls"):
    plot(ax[0], e2[s], s)
ax[0].set_xlabel("Outage length (min)"); ax[0].set_ylabel("Sync time (s)"); ax[0].set_title("(a) Synchronization")
ax[0].xaxis.set_major_locator(FixedLocator([1, 5, 10, 20]))
for s in ("ofcc", "ha", "cl", "cls"):
    plot(ax[1], sysl[s], s)
for n in (3, 4, 5):
    plot(ax[2], scal[n], n)
plain = FuncFormatter(lambda v, _: f"{v:g}")
loads = [50, 100, 200, 400, 800, 1600]
for a, title in ((ax[1], "(b) Latency, 4 orgs"), (ax[2], "(c) OFCC, 3-5 orgs")):
    a.set_xscale("log"); a.set_yscale("log")
    a.xaxis.set_major_locator(FixedLocator(loads)); a.xaxis.set_major_formatter(plain); a.xaxis.set_minor_locator(NullLocator())
    a.yaxis.set_major_locator(FixedLocator([0.1, 1, 10, 100])); a.yaxis.set_major_formatter(plain)
    a.yaxis.set_minor_locator(NullLocator())
    a.set_ylim(0.03, 400); a.tick_params(axis="x", labelrotation=45)
    a.set_xlabel("Offered load (items/s)"); a.set_title(title)
ax[1].set_ylabel("Item p95 latency (s)")
for a in ax:
    a.grid(True, lw=0.3, color="#dddddd"); a.set_axisbelow(True)
ax[0].legend(frameon=False, loc="upper left", handlelength=2.2)
ax[2].legend(frameon=False, loc="upper left", handlelength=2.2)
fig.savefig(stem + ".pdf"); fig.savefig(stem + ".png", dpi=1200)
print("wrote", stem + ".pdf")
