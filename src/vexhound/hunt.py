"""
hunt.py: unified angr/VEX-IR stack-overflow hunting harness.

This is the top-level "harness": point it at one or more firmware binaries and
it reports stack-buffer-overflow sites (plus command injection / format string)
found entirely from lifted VEX IR: no execution.

It combines two IR analyses:

  * PROVER  (prover.OverflowProver)
        per-call-site proof: recovers dest buffer offset + size argument from
        the IR, computes room = saved_ra - dest, and decides OVERFLOW / SAFE /
        CANDIDATE. A forward taint pass (taint) marks a site CONFIRMED when
        attacker input provably reaches it. Precise; suppresses bounded copies.

  * HEURISTIC (scan.VexScan)
        presence + distance signature over the same IR. Broad recall; used as a
        fallback for functions the prover's frame model cannot handle (x86_64
        implicit-return frames, AArch64 fp-relative locals) so recall never
        regresses, and for the command-injection / format-string families the
        prover does not cover.

Merge policy (per function):
  - prover OVERFLOW/CANDIDATE site        -> PROVEN row (CONFIRMED if tainted)
  - heuristic F1 on a function the prover proved entirely SAFE  -> SUPPRESSED
  - heuristic F1 where the prover was UNMODELED / saw no sink    -> HEURISTIC row
  - heuristic command-injection / format-string                 -> HEURISTIC row

Usage:
  python3 hunt.py FIRMWARE_BIN [more ...] [--json out.json] [--csv out.csv]
  python3 hunt.py --overflows-only corpus/dir645_cgibin_mipsle
"""
import logging

logging.disable(logging.CRITICAL)
import csv
import json
import os
import sys
from collections import OrderedDict

from . import banner
from .prover import OverflowProver
from .scan import elf_mitigations, mitigations_str

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "-": 3}


def _status(r):
    """Colored reachability tag for a finding row."""
    if r.get("tainted") is None:
        return ""
    if r["tainted"]:
        return banner.paint("CONFIRMED", banner.GREEN, bold=True)
    return banner.paint("candidate", banner.MUTED)


def _mit_glyphs(mit, g):
    """Render mitigations as colored check/cross flags (green=on, muted=off)."""
    out = []
    for key in ("canary", "nx", "pie"):
        v = mit.get(key)
        mark = g["ok"] if v else g["no"] if v is False else "?"
        out.append(banner.paint(f"{key} {mark}", banner.GREEN if v else banner.MUTED))
    relro = mit.get("relro") or "?"
    out.append(banner.paint(f"relro {relro}",
                            banner.GREEN if relro == "full" else banner.MUTED))
    return banner.paint(f" {g['dot']} ", banner.MUTED).join(out)


def hunt(path):
    """Return (arch_name, [rows]) for one binary. Each row is a dict."""
    prov = OverflowProver(path)
    arch = prov.vs.arch.name
    pf = prov.run()

    # per-function prover summary
    by_fn = {}
    for f in pf:
        by_fn.setdefault(f["function"], []).append(f)
    proven_ovf = {fn: [x for x in v if x["verdict"] in ("OVERFLOW", "CANDIDATE")]
                  for fn, v in by_fn.items()}
    has_unmodeled = {fn: any(x["verdict"] == "UNMODELED" for x in v)
                     for fn, v in by_fn.items()}

    rows = []
    # 1) precise prover findings
    seen_sites = set()                         # collapse overlapping-block duplicates
    for fn, sites in proven_ovf.items():
        for s in sites:
            key = (fn, s["sink"], s.get("site", s["call"]))
            if key in seen_sites:
                continue
            seen_sites.add(key)
            rows.append({
                "function": fn, "family": "stack-buffer-overflow",
                "sink": s["sink"], "addr": s["call"], "site": s.get("site", s["call"]),
                "method": "PROVEN",
                "verdict": s["verdict"],
                "severity": s["severity"],
                "tainted": s["tainted"],
                "dest": s["dest"], "size": s["size"], "room": s["room"],
                "note": s["reason"],
            })

    # 2) heuristic findings, merged. Reuse the prover's already-loaded VexScan
    # (binary + CFG) instead of loading the whole thing a second time.
    seen_supp = 0
    for h in prov.vs.run():
        fn = h["function"]
        fam = h["family"]
        if fam == "stack-buffer-overflow":
            if proven_ovf.get(fn):
                continue                      # already covered precisely
            if fn in by_fn and not has_unmodeled.get(fn):
                seen_supp += 1                # prover proved this fn safe: drop FP
                continue
            # prover could not model this fn (or saw no sink): keep for recall
            rows.append({
                "function": fn, "family": fam, "sink": "", "addr": h["addr"],
                "method": "HEURISTIC", "verdict": "CANDIDATE",
                "severity": h["severity"], "tainted": None,
                "dest": "", "size": "", "room": "",
                "note": h["note"] + " | " + h.get("detail", ""),
            })
        elif fam in ("command-injection", "format-string", "error"):
            rows.append({
                "function": fn, "family": fam, "sink": "", "addr": h["addr"],
                "method": "HEURISTIC", "verdict": "CANDIDATE",
                "severity": h["severity"], "tainted": None,
                "dest": "", "size": "", "room": "",
                "note": h["note"] + " | " + h.get("detail", ""),
            })
    rows.sort(key=lambda r: (SEV_RANK.get(r["severity"], 9),
                             r["method"] != "PROVEN", r["function"]))
    mstr = mitigations_str(getattr(prov.vs, "mitigations", None))
    for r in rows:
        r["mitigations"] = mstr
    return arch, rows, seen_supp


def run(paths, json_out=None, csv_out=None, overflows_only=False):
    """Analyze each binary, print findings, and optionally dump JSON/CSV.

    Returns a process exit code: 0 if every target loaded, 2 if every target
    failed to load, 1 if some did. Findings do not affect the exit code."""
    only = overflows_only
    all_rows = []
    errors = 0
    g = banner.glyphs()
    for p in paths:
        print(banner.rule(os.path.basename(p)))
        try:
            arch, rows, supp = hunt(p)
        except Exception as e:
            print("  " + banner.paint("load error", banner.RED, bold=True)
                  + f": {type(e).__name__}: {e}")
            errors += 1
            continue
        mit = elf_mitigations(p)
        print("  " + banner.paint("arch ", banner.MUTED) + arch
              + banner.paint("   mitigations ", banner.MUTED) + _mit_glyphs(mit, g))
        if mit.get("canary"):
            print("  " + banner.paint("note ", banner.AMBER)
                  + banner.paint("stack canary present; a saved-ra overwrite is likely "
                                 "caught at return (DoS), not a clean hijack", banner.MUTED))
        show = [r for r in rows if r["family"] == "stack-buffer-overflow"] if only else rows
        if not show:
            print("  " + banner.paint("(no findings)", banner.MUTED))
        # group findings under their function so the output reads as a tree
        by_fn = OrderedDict()
        for r in show:
            by_fn.setdefault(r["function"], []).append(r)
        for fn, frs in by_fn.items():
            print("  " + banner.paint(fn, banner.CREAM, bold=True))
            for i, r in enumerate(frs):
                last = i == len(frs) - 1
                branch, cont = (g["elbow"], g["gap"]) if last else (g["tee"], g["pipe"])
                loc = f"{r['sink']}@{r.get('site', r['addr'])}" if r["sink"] else f"@{r['addr']}"
                print("  " + banner.paint(branch, banner.MUTED)
                      + banner.severity_label(r["severity"]) + " "
                      + banner.paint(f"{loc:<26}", banner.CREAM) + " "
                      + _status(r) + "  " + banner.paint(r["method"].lower(), banner.MUTED))
                pre = "  " + banner.paint(cont, banner.MUTED)
                if r["dest"]:
                    print(pre + banner.paint(
                        f"dest {r['dest']}  room {r['room']}  size {r['size']}", banner.MUTED))
                print(pre + banner.paint(r["note"], banner.MUTED))
        proven = sum(1 for r in rows if r["method"] == "PROVEN")
        heur = sum(1 for r in rows if r["method"] == "HEURISTIC")
        sep = banner.paint(f" {g['dot']} ", banner.MUTED)
        print("  " + banner.paint(g["h"] * 2 + " ", banner.MUTED)
              + banner.paint(f"{proven} proven", banner.RED, bold=proven > 0) + sep
              + banner.paint(f"{heur} heuristic", banner.AMBER) + sep
              + banner.paint(f"{supp} suppressed", banner.MUTED))
        for r in rows:
            r["binary"] = p
            r["arch"] = arch
            all_rows.append(r)

    if json_out:
        json.dump(all_rows, open(json_out, "w"), indent=2)
        print(f"\n[+] wrote {json_out} ({len(all_rows)} rows)")
    if csv_out:
        cols = ["binary", "arch", "function", "family", "method", "verdict",
                "severity", "tainted", "sink", "addr", "site", "dest", "size",
                "room", "mitigations", "note"]
        with open(csv_out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in all_rows:
                w.writerow(r)
        print(f"[+] wrote {csv_out} ({len(all_rows)} rows)")

    if errors == 0:
        return 0
    return 2 if errors == len(paths) else 1


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="vexhound hunt",
        description="Prove stack-buffer overflows in firmware binaries from VEX IR.")
    ap.add_argument("targets", nargs="+", help="binaries to analyze")
    ap.add_argument("--json", metavar="FILE", help="write findings as JSON")
    ap.add_argument("--csv", metavar="FILE", help="write findings as CSV")
    ap.add_argument("--overflows-only", action="store_true",
                    help="show only stack-overflow findings, hide cmdi/format-string")
    a = ap.parse_args(argv)
    banner.set_enabled(banner.stdout_supports_color())   # standalone run: honor TTY/NO_COLOR
    return run(a.targets, a.json, a.csv, a.overflows_only)


if __name__ == "__main__":
    sys.exit(main())
