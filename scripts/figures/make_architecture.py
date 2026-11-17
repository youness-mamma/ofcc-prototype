#!/usr/bin/env python3
"""Generate the OFCC architecture diagram (figure01) as an editable .drawio file and render it offline.

The .drawio file opens and stays editable in the VS Code draw.io extension (hediet.vscode-drawio).
Rendering uses that extension's bundled draw.io engine (viewer-static.min.js, draw.io 32.6.10)
inside headless Chrome. No online service is used.

Logos: official files only, see logos/SOURCES.txt. They are embedded unmodified (Fabric: viewBox
cropped to the mark, artwork unchanged).

Outputs:
  code/results/figures/figure01.drawio   (editable source)
  <paper>/figure01.pdf                    (vector, cropped)
  <paper>/figure01.png                    (1200 dpi backup)
"""
import base64, html, json, pathlib, subprocess, tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]                                   # paper folder
OUT_DRAWIO = ROOT / "code/results/figures/figure01.drawio"
OUT_PDF = ROOT / "figure01.pdf"
OUT_PNG = ROOT / "figure01.png"
VIEWER = pathlib.Path.home() / ".vscode/extensions/hediet.vscode-drawio-1.19.0/drawio/src/main/webapp/js/viewer-static.min.js"

W, H = 700, 550
FONT = 15            # px; about 7.2 pt once the figure is scaled to the LNCS text width (4.8 in)
TXT = "#1F1F1F"
ZONE_V = ("#EEF2F6", "#8A99A8")
ZONE_S = ("#F4F2ED", "#A39E93")
BOX_V = ("#DCE6F0", "#5B6F82")
BOX_S = ("#E9E3D7", "#7D7466")
WHITE = ("#FFFFFF", "#6E6E6E")
EDGE = "#3A3A3A"
BASE = f"html=1;whiteSpace=wrap;fontColor={TXT};fontStyle=1;fontSize={FONT};fontFamily=Helvetica;"

cells = []

def add(cid, style, x, y, w, h, label=""):
    cells.append(f'<mxCell id="{cid}" value="{html.escape(label)}" style="{style}" vertex="1" parent="1">'
                 f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')

def box(cid, x, y, w, h, label, colors, extra=""):
    add(cid, BASE + f"rounded=1;arcSize=8;fillColor={colors[0]};strokeColor={colors[1]};spacing=4;{extra}", x, y, w, h, label)

def store(cid, x, y, w, h, label, colors, extra=""):
    add(cid, BASE + f"shape=cylinder3;boundedLbl=1;backgroundOutline=1;size=7;fillColor={colors[0]};"
             f"strokeColor={colors[1]};spacing=4;{extra}", x, y, w, h, label)

def zone(cid, x, y, w, h, label, colors, dashed=False, extra=""):
    add(cid, BASE + f"rounded=0;fillColor={colors[0]};strokeColor={colors[1]};verticalAlign=top;align=left;"
             f"spacingLeft=8;spacingTop=2;{'dashed=1;' if dashed else ''}{extra}", x, y, w, h, label)

def text(cid, x, y, w, h, label, align="left", note=False):
    color, fs = ("#4A4A4A", 3) if note else (TXT, 1)
    add(cid, f"text;html=1;whiteSpace=wrap;fontColor={color};fontStyle={fs};fontSize={FONT};fontFamily=Helvetica;"
             f"align={align};verticalAlign=middle;", x, y, w, h, label)

def logo(cid, x, y, w, h, svg_file):
    b64 = base64.b64encode((HERE / "logos" / svg_file).read_bytes()).decode()
    add(cid, f"shape=image;aspect=fixed;imageAspect=1;verticalLabelPosition=bottom;image=data:image/svg+xml,{b64};", x, y, w, h)

def edge(cid, pts, dashed=False):
    (sx, sy), (tx, ty) = pts[0], pts[-1]
    way = "".join(f'<mxPoint x="{x}" y="{y}"/>' for x, y in pts[1:-1])
    arr = f'<Array as="points">{way}</Array>' if way else ""
    style = (f"endArrow=block;endFill=1;endSize=6;html=1;strokeColor={EDGE};strokeWidth=1.5;rounded=0;"
             f"{'dashed=1;dashPattern=6 4;' if dashed else ''}")
    cells.append(f'<mxCell id="{cid}" style="{style}" edge="1" parent="1"><mxGeometry relative="1" as="geometry">'
                 f'<mxPoint x="{sx}" y="{sy}" as="sourcePoint"/><mxPoint x="{tx}" y="{ty}" as="targetPoint"/>{arr}'
                 f'</mxGeometry></mxCell>')

def icon(cid, x, y, w, h, shape, fill="#FFFFFF", stroke="#4A4A4A"):
    """Standard draw.io stencil shape (built-in libraries), muted monochrome."""
    add(cid, f"shape={shape};html=1;aspect=fixed;fillColor={fill};strokeColor={stroke};strokeWidth=1;", x, y, w, h)

KEY, SERVER = "mxgraph.office.security.key_permissions", "mxgraph.networks.server"
WORKST, USERS = "mxgraph.office.devices.workstation", "mxgraph.office.users.users"

# ---------------- vessel ----------------
zone("zv", 0, 0, W, 170, "Vessel (operates offline)", ZONE_V)
box("sens", 10, 50, 120, 104, "Onboard sensors and systems", BOX_V)
zone("gw", 146, 28, 546, 134, "Evidence gateway", WHITE, dashed=True)
box("cap", 156, 58, 124, 52, "Capture and encrypt", BOX_V)
store("chain", 300, 52, 140, 62, "Local custody chain", BOX_V)
box("prot", 300, 118, 140, 38, "Protected key and counter", BOX_V, "fontSize=14;spacingLeft=24;")
icon("i_key", 306, 123, 18, 28, KEY, fill=BOX_V[0])
box("sync", 548, 58, 134, 96, "Sync agent (runs on reconnection)", BOX_V)
edge("e1", [(130, 84), (156, 84)])
edge("e2", [(280, 84), (300, 84)])
edge("e3", [(440, 84), (548, 84)])
text("t3", 446, 60, 98, 22, "entries", align="center")
edge("e4", [(440, 137), (548, 137)])
text("t4", 446, 113, 98, 22, "header", align="center")

# ---------------- link band ----------------
text("link", 10, 185, 200, 40, "Intermittent link to shore", note=True)

# ---------------- shore ----------------
zone("zs", 0, 240, W, 310, "Shore (consortium of organizations)", ZONE_S)
# Fabric network
zone("fab", 10, 266, 560, 196, "", WHITE)
logo("fablogo", 18, 272, 30, 25, "fabric_mark.svg")
text("fabt", 54, 270, 260, 28, "Hyperledger Fabric network")
for cid, x, y, lab in [("p1", 20, 304, "Org 1 peer"), ("p2", 175, 304, "Org 2 peer"),
                       ("p3", 20, 352, "Org 3 peer"), ("p4", 175, 352, "Org 4 peer")]:
    box(cid, x, y, 145, 40, lab, BOX_S, "spacingLeft=26;")
    icon("i_" + cid, x + 8, y + 7, 20, 26, SERVER, fill=BOX_S[0])
box("ca", 20, 402, 300, 48, "Fabric identities (X.509) and role table", BOX_S)
box("cc", 330, 304, 234, 70, "Custody chaincode: batch checks, gaps, custody transfers, access policy", BOX_S)
box("ord", 330, 384, 234, 66, "Ordering service (three Raft orderers)", BOX_S)
# off-chain store and verifier
store("st", 586, 266, 104, 100, "Encrypted object store", BOX_S, "verticalAlign=bottom;spacingBottom=6;")
logo("miniologo", 596, 286, 84, 13, "minio.svg")
box("vf", 586, 388, 104, 74, "Verifier tool", BOX_S, "verticalAlign=bottom;spacingBottom=6;")
icon("i_vf", 622, 394, 32, 32, WORKST, fill=BOX_S[0])
edge("e_sv", [(638, 366), (638, 388)])
edge("e_fv", [(570, 425), (586, 425)])
# people
box("kh", 10, 500, 200, 40, "Key holder of each organization", BOX_S, "fontSize=14;spacingLeft=24;")
icon("i_kh", 16, 505, 18, 28, KEY, fill=BOX_S[0])
box("ro", 330, 500, 234, 40, "Collector, investigator, auditor", BOX_S, "spacingLeft=34;")
icon("i_ro", 336, 504, 32, 32, USERS, fill=BOX_S[0])
edge("e_ro", [(447, 500), (447, 462)])
text("t_ro", 214, 468, 228, 24, "custody transfers, queries", align="right")
edge("e_kr", [(210, 520), (330, 520)])
text("t_kr", 214, 496, 112, 22, "content key*", align="center")

# ---------------- cross-link edges (dashed: only when the link is up) ----------------
edge("e_cc", [(560, 154), (560, 304)], dashed=True)
text("t_cc", 356, 190, 198, 24, "signed batch of entries", align="right")
edge("e_st", [(660, 154), (660, 266)], dashed=True)
text("t_st", 566, 182, 90, 44, "encrypted payloads", align="left")

model = ('<mxGraphModel dx="0" dy="0" grid="1" gridSize="2" page="1" pageScale="1" '
         f'pageWidth="{W}" pageHeight="{H}"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
         + "".join(cells) + "</root></mxGraphModel>")
OUT_DRAWIO.write_text(f'<mxfile host="script"><diagram id="arch" name="OFCC architecture">{model}</diagram></mxfile>')

page = f"""<!doctype html><html><head><meta charset="utf-8">
<style>@page {{ size: {W+20}px {H+20}px; margin: 0 }} html,body {{ margin:0; padding:0; background:#fff }}</style>
<script src="file://{VIEWER}"></script><script src="file://{VIEWER.parent / 'stencils.min.js'}"></script></head><body><div id="g" style="width:{W+20}px;height:{H+20}px"></div>
<script>
var doc = mxUtils.parseXml({json.dumps(model)});
new GraphViewer(document.getElementById('g'), doc.documentElement,
                {{toolbar:null, nav:false, lightbox:false, border:8, center:false}});
</script></body></html>"""

with tempfile.TemporaryDirectory() as td:
    hp = pathlib.Path(td) / "fig.html"; hp.write_text(page)
    raw = pathlib.Path(td) / "raw.pdf"
    subprocess.run(["google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox",
                    "--allow-file-access-from-files", "--virtual-time-budget=8000",
                    "--no-pdf-header-footer", f"--print-to-pdf={raw}", hp.as_uri()],
                   check=True, capture_output=True)
    subprocess.run(["pdfcrop", "--margins", "2", str(raw), str(OUT_PDF)], check=True, capture_output=True)
subprocess.run(["pdftoppm", "-r", "1200", "-png", "-singlefile", str(OUT_PDF), str(OUT_PNG.with_suffix(""))], check=True)
print("wrote", OUT_DRAWIO, OUT_PDF, OUT_PNG)
