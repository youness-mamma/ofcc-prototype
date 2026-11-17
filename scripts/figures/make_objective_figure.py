#!/usr/bin/env python3
"""Fig. 2 (figure02): does each system keep custody verifiable across outages? Adaptive adversary, five test seeds pooled.
(a) tampering of the offline store or in transit before upload; (b) tampering of the off-chain store or
CL server after upload (operations that apply); (c) forged or rewritten custody transfers.
Share caught or blocked vs accepted as genuine.
Usage: make_objective_figure.py <raw_dir> <out_stem>  -> <out_stem>.pdf (vector) and .png (1200 dpi)
"""
import glob, json, os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "checks"))
from scoring import rescore

matplotlib.rcParams.update({"pdf.fonttype": 42, "ps.fonttype": 42, "font.size": 7, "font.family": "DejaVu Sans",
                            "axes.linewidth": 0.6, "xtick.labelsize": 6.5, "ytick.labelsize": 7,
                            "hatch.linewidth": 0.5})
raw, stem = sys.argv[1], sys.argv[2]
SYSTEMS = [("ofcc", "OFCC"), ("noProt", "noProt"), ("noSig", "noSig"), ("cls", "CL-S"), ("ha", "HA"), ("cl", "CL")]
DARK, LIGHT = "#1b3a5c", "#d9d9d9"

res = {}
for s, lab in SYSTEMS:
    ok = [0, 0, 0]
    n = [0, 0, 0]
    for f in sorted(glob.glob(os.path.join(raw, f"e1_{s}_adaptive_seed*.json"))):
        d = json.load(open(f))
        ops = [o for o in rescore(d) if not o.get("na")]
        for i, pos in enumerate(("pre", "post")):
            sel = [o for o in ops if o["pos"] == pos]
            n[i] += len(sel)
            ok[i] += sum(o["detected"] for o in sel)
        cust = d.get("custody_attacks") or []
        n[2] += len(cust)
        ok[2] += sum(c["outcome"] in ("prevented", "detected") for c in cust)
    res[lab] = [100 * ok[i] / n[i] for i in range(3)], n

fig, axes = plt.subplots(1, 3, figsize=(4.8, 1.7), sharey=True, constrained_layout=True)
titles = ["(a) Tampered while offline", "(b) Tampered after upload", "(c) Custody forged"]
good = ["caught", "blocked or caught", "verified, custody complete"]
bad = ["accepted as genuine", "accepted", "flagged or incomplete"]
labs = [lab for _, lab in SYSTEMS][::-1]
for i, ax in enumerate(axes):
    v = [res[l][0][i] for l in labs]
    ax.barh(labs, v, color=DARK, height=0.62, lw=0)
    ax.barh(labs, [100 - x for x in v], left=v, color=LIGHT, height=0.62, lw=0.4, edgecolor="#777777", hatch="////")
    for y, x in enumerate(v):
        txt = f"{x:.0f}"
        ax.text(103, y, txt, va="center", ha="left", fontsize=6, clip_on=False,
                fontweight="bold" if x >= 99.95 else "normal")
    ax.set_xlim(0, 100)
    ax.set_xticks([0, 50, 100])
    ax.set_title(titles[i], fontsize=7)
    ax.set_xlabel("% of " + ["operations", "operations", "attacks"][i])
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.tick_params(axis="y", length=0)
h1 = plt.Rectangle((0, 0), 1, 1, color=DARK)
h2 = plt.Rectangle((0, 0), 1, 1, fc=LIGHT, ec="#777777", hatch="////", lw=0.4)
fig.legend([h1, h2], ["caught or blocked (number = %)", "accepted as genuine"],
           loc="outside lower center", ncol=2, frameon=False, fontsize=6.5)
fig.savefig(stem + ".pdf")
fig.savefig(stem + ".png", dpi=1200)
print("wrote", stem + ".pdf")
for l in labs[::-1]:
    print(f"{l:7s}", [round(x, 2) for x in res[l][0]], res[l][1])
