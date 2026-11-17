#!/usr/bin/env python3
"""Check that every number in main.tex comes from results (numbers.json) or a documented setting.

Usage: check_paper_numbers.py <main.tex> <numbers.json> <config_numbers.json>
A printed number matches a result if some value in numbers.json rounds to it at the printed precision
(also tried as a percentage, i.e. value*100). Prints unmatched numbers with context; exit 1 if any.
"""
import json, re, sys

tex, numf, cfgf = sys.argv[1:4]
t = open(tex).read()
body = t[t.index(r"\begin{document}"):t.index(r"\bibliography")]
# drop things whose digits are not claims
for pat in (r"\\cite\{[^}]*\}", r"\\ref\{[^}]*\}", r"\\label\{[^}]*\}", r"\\includegraphics(\[[^\]]*\])?\{[^}]*\}",
            r"\\(sub)*section\*?\{[^}]*\}", r"%[^\n]*", r"\\begin\{(equation|align)\*?\}.*?\\end\{(equation|align)\*?\}",
            r"\$[^$]*\$", r"\\(v|h)space\{[^}]*\}", r"\\email\{[^}]*\}", r"\\institute\{.*?\}\s*\\maketitle",
            r"\\pending\{[^}]*\}", r"@\{\}", r"\\cmidrule\([^)]*\)\{[^}]*\}", r"\\multicolumn\{\d+\}", r"p\{0\.\d+\\textwidth\}"):
    body = re.sub(pat, " ", body, flags=re.S)
vals = []
def walk(x):
    if isinstance(x, (int, float)) and not isinstance(x, bool):
        vals.append(float(x))
    elif isinstance(x, dict):
        for v in x.values():
            walk(v)
    elif isinstance(x, list):
        for v in x:
            walk(v)
walk(json.load(open(numf)))
cfg = json.load(open(cfgf))

def matches(tok):
    s = tok.replace(",", "")
    try:
        x = float(s)
    except ValueError:
        return False
    dec = len(s.split(".")[1]) if "." in s else 0
    for v in vals:
        for cand in (v, v * 100, abs(v), abs(v) * 100):
            if round(cand, dec) == round(x, dec):
                return True
    return False

bad, ok_res, ok_cfg = [], 0, 0
for m in re.finditer(r"(?<![A-Za-z0-9.\\])[-+]?\d[\d,]*(\.\d+)?", body):
    tok = m.group(0)
    if tok.strip("+-") in cfg or tok in cfg:
        ok_cfg += 1
    elif matches(tok):
        ok_res += 1
    else:
        ctx = body[max(0, m.start() - 50):m.end() + 30].replace("\n", " ")
        bad.append((tok, " ".join(ctx.split())))
print(f"numbers matched to results: {ok_res}; to documented settings: {ok_cfg}; UNMATCHED: {len(bad)}")
for tok, ctx in bad:
    print(f"  {tok:>8s}  ...{ctx}...")
sys.exit(1 if bad else 0)
