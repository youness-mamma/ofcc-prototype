"""Detection scoring shared by summarize.py and make_tables.py (stdlib only).

Pre-upload operation in round r of gateway g is detected iff some alert of gateway g falls in round r or
r+1 (same or next synchronization), counting synchronization-time alerts and verifier alerts that name
the altered or missing item. Two verifier alert kinds are not credited to pre-upload operations:
  * CL 'chain': a broken server-side hash chain can only be caused by editing after upload;
  * verifier duplicate reports ('dupseq' with a named item): they name the ORIGINAL copy of a replayed
    record, whose round is unrelated; the duplicate is already reported at ingestion in the right round.
Post-upload operations keep the runner's flag (an alert names the target item or the inserted object).
"""


def credited(a):
    if a["kind"] == "chain":
        return False
    if a["kind"] == "dupseq" and a.get("orig", -1) >= 0:
        return False
    return True


def rescore(d):
    """Return a copy of the ops list with 'detected' recomputed for pre-upload operations."""
    alerts = [a for a in (d["alerts"] or []) if credited(a)]
    by = {}
    for a in alerts:
        by.setdefault((a["gw"], a["round"]), True)
    out = []
    for o in d["ops"]:
        o = dict(o)
        if o["pos"] == "pre" and not o.get("na"):
            o["detected"] = bool(by.get((o["gw"], o["round"])) or by.get((o["gw"], o["round"] + 1)))
        out.append(o)
    return out
