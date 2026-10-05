"""
rules.py - a fast IR RULE CATALOG that consumes the ranked
candidates from candidates.py and gives each one a static VERDICT:

  CONFIRMED       the static rule proves the bug (actionable now)
  REFUTED         the static rule proves it is NOT a bug (drop it)
  NEEDS_SYMBOLIC  static cannot decide -> hand to the symbolic stage

Per bug class the rule is:
  overflow  reuse the OverflowProver verdict at the sink call site (dest/size/room):
              OVERFLOW -> CONFIRMED, SAFE -> REFUTED, else NEEDS_SYMBOLIC
  cmdi      the tainted argument is the command argument (arg0) of system/exec
              -> CONFIRMED (attacker data reaches the shell), else NEEDS_SYMBOLIC
  fmt       the tainted argument is the FORMAT argument itself
              -> CONFIRMED (classic format string); only data args tainted -> REFUTED
  alloc     attacker-controlled size into malloc/realloc -> NEEDS_SYMBOLIC (int/heap)
  uaf       temporal, always NEEDS_SYMBOLIC (needs heap-state modeling)

Static only. Reuses candidates.CandidateBuilder (Parts 1+2) and
prover.OverflowProver (the overflow oracle).
"""
import logging

logging.disable(logging.CRITICAL)
import csv
import json
import os
import sys

from .candidates import CandidateBuilder
from .prover import OverflowProver

# which argument index is the FORMAT string for each printf-family sink
FMT_ARG = {"printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1,
           "sprintf": 1, "snprintf": 2, "syslog": 1, "err": 1, "warn": 1}
# which argument index is the command for each exec-family sink
CMD_ARG = {"system": 0, "popen": 0, "execl": 0, "execlp": 0,
           "execv": 0, "execve": 0, "execvp": 0}

ROUTE_ORDER = {"CONFIRMED": 0, "NEEDS_SYMBOLIC": 1, "REFUTED": 2}


class RuleEngine:
    def __init__(self, path):
        from .scan import VexScan
        vs = VexScan(path)                          # load the binary once for every stage
        self.cb = CandidateBuilder(path, vs=vs)     # Parts 1 + 2
        self.cands = self.cb.build()
        self.arch = self.cb.arch
        # overflow oracle: OverflowProver verdict indexed by sink call address.
        # Reuse the loaded VexScan and the summary's taint engine, so the whole
        # pipeline lifts the binary and builds its CFG exactly once.
        self.pf = {}
        try:
            prover = OverflowProver(path, vs=vs, taint=self.cb.eng.te)
            for f in prover.run():
                self.pf.setdefault(f["call"], f)    # f["call"] is hex(call addr)
        except Exception:
            pass
        self._surface_proven_overflows()

    def _surface_proven_overflows(self):
        """Candidates come from inter-procedural taint flows, but the OverflowProver
        proves overflows from stack geometry independently. When a target routes
        request data through global buffers or a function-pointer dispatch table (as
        stripped vendor httpds do), the may-analysis taint never links a source to
        the sink, so a real, proven overflow yields no flow and would be dropped.
        Surface every proven OVERFLOW that no flow candidate already covers, tagged
        `prover_only` so the verdict rule can confirm the ones the prover's own taint
        shows are attacker-reachable and leave the spatial-only ones as
        NEEDS_SYMBOLIC leads (see _rule)."""
        covered = {c["addr"] for c in self.cands}
        extra = []
        for f in self.pf.values():
            if f.get("verdict") != "OVERFLOW" or f.get("call") in covered:
                continue
            fn = f.get("function") or "?"
            fa = self.cb.eng.name2addr.get(fn)
            path, reachable = self.cb._path_to(fa) if fa is not None else ([fn], False)
            sev = f.get("severity") or "HIGH"
            hit = bool(f.get("tainted"))
            extra.append({
                "cls": "overflow", "function": fn, "sink": f["sink"], "addr": f["call"],
                "tainted_arg": "?", "prover_only": True,
                "sources": ("attacker input reaches the sink" if hit
                            else "spatial overflow; attacker-reachability not established"),
                "path": " -> ".join(path), "reachable": reachable,
                "score": (10 if sev == "CRITICAL" else 8) + (2 if hit else 0),
                "severity": sev, "confidence": "flow" if hit else "candidate",
            })
        if not extra:
            return
        self.cands.extend(extra)
        self.cands.sort(key=lambda x: (-x["score"], x["cls"], x["function"]))
        for i, c in enumerate(self.cands, 1):
            c["rank"] = i

    def _tainted_args(self, c):
        """set of integer arg indices from the candidate's 'argN,argM' string."""
        out = set()
        for tok in c["tainted_arg"].split(","):
            tok = tok.strip()
            if tok.startswith("arg") and tok[3:].isdigit():
                out.add(int(tok[3:]))
        return out

    def _rule(self, c):
        cls = c["cls"]
        if cls == "overflow":
            fnd = self.pf.get(c["addr"])
            if fnd is None:
                return ("NEEDS_SYMBOLIC", ("overflow sink not modeled by the prover "
                        "(fp-frame / unresolved dest); confirm reachability + size"))
            v = fnd["verdict"]
            if v == "OVERFLOW":
                if c.get("prover_only") and not fnd.get("tainted"):
                    return ("NEEDS_SYMBOLIC", (f"prover: spatial overflow proven ({fnd['reason']}); "
                            "attacker-reachability to the sink not established"))
                return ("CONFIRMED", f"prover: {fnd['reason']}")
            if v in ("SAFE", "NOT_STACK"):
                return ("REFUTED", f"prover: {fnd['reason']}")
            return ("NEEDS_SYMBOLIC", (f"prover: {v} (dest {fnd.get('dest')}, "
                    f"room {fnd.get('room')}); needs a solved length"))
        if cls == "cmdi":
            ci = CMD_ARG.get(c["sink"])
            if ci is not None and ci in self._tainted_args(c):
                return ("CONFIRMED", (f"attacker data reaches {c['sink']} arg{ci} "
                        "(the command); verify no sanitizer on the path"))
            return ("NEEDS_SYMBOLIC", ("taint reaches an exec sink but not proven to be "
                    "the command argument"))
        if cls == "fmt":
            fi = FMT_ARG.get(c["sink"])
            ta = self._tainted_args(c)
            if fi is not None and fi in ta:
                return ("CONFIRMED", (f"the format argument ({c['sink']} arg{fi}) is "
                        "attacker-controlled: classic format string"))
            return ("REFUTED", ("only data arguments are attacker-controlled; the format "
                    "string is constant, so this is a benign %s-style use"))
        if cls == "alloc":
            return ("NEEDS_SYMBOLIC", ("attacker-influenced allocation size; needs "
                    "arithmetic/overflow reasoning"))
        if cls == "uaf":
            return ("NEEDS_SYMBOLIC", ("temporal (use-after-free / double-free); needs "
                    "heap-state modeling in the symbolic stage"))
        return ("NEEDS_SYMBOLIC", "unclassified")

    def run(self):
        out = []
        for c in self.cands:
            verdict, why = self._rule(c)
            row = dict(c)
            row["verdict"] = verdict
            row["evidence"] = why
            out.append(row)
        out.sort(key=lambda r: (ROUTE_ORDER.get(r["verdict"], 9), -r["score"]))
        return out


def _report_path(report, idx, path):
    """One --report FILE for a single target; for extra targets, suffix the name."""
    if idx == 0:
        return report
    stem, ext = os.path.splitext(report)
    return f"{stem}.{os.path.splitext(os.path.basename(path))[0]}{ext or '.html'}"


def run(paths, json_out=None, csv_out=None, report=None, run_symbolic=False,
        ghidra_home=None):
    """Run the static pipeline (classify, candidates, per-class verdicts) on each
    target, print a verdict table, and optionally dump JSON/CSV or an HTML report."""
    all_rows = []
    from . import banner
    from .scan import elf_mitigations, mitigations_str
    vcolor = {"CONFIRMED": banner.RED, "NEEDS_SYMBOLIC": banner.AMBER,
              "REFUTED": banner.GREEN}
    g = banner.glyphs()
    for idx, p in enumerate(paths):
        print(banner.rule(os.path.basename(p)))
        print("  " + banner.paint("mitigations ", banner.MUTED)
              + banner.paint(mitigations_str(elf_mitigations(p)), banner.MUTED))
        engine = RuleEngine(p)
        rows = engine.run()
        from collections import Counter
        c = Counter(r["verdict"] for r in rows)
        sep = banner.paint(f" {g['dot']} ", banner.MUTED)
        print("  " + banner.paint(f"{len(rows)} candidates", banner.CREAM, bold=True) + "  "
              + banner.paint(f"{c.get('CONFIRMED', 0)} confirmed", banner.RED) + sep
              + banner.paint(f"{c.get('NEEDS_SYMBOLIC', 0)} needs-symbolic", banner.AMBER) + sep
              + banner.paint(f"{c.get('REFUTED', 0)} refuted", banner.GREEN) + "\n")
        for r in rows:
            print("  " + banner.paint(f"{r['verdict']:<14}", vcolor.get(r["verdict"], banner.MUTED),
                                      bold=(r["verdict"] == "CONFIRMED")) + " "
                  + banner.paint(f"{r['cls']:<8}", banner.CYAN) + " "
                  + banner.paint(f"{r['sink']}@{r['addr']}", banner.CREAM) + "  "
                  + banner.paint(f"{r['function']}", banner.MUTED)
                  + banner.paint(f"  (score {r['score']})", banner.MUTED))
            print("     " + banner.paint(g["dot"], banner.MUTED) + " "
                  + banner.paint(r["evidence"], banner.MUTED))
        if report:
            from . import report as report_mod
            gh = report_mod.find_ghidra_home(ghidra_home)
            if gh:
                print("  " + banner.paint(f"{g['dot']} decompiling with Ghidra at {gh}",
                                          banner.MUTED))
            else:
                print("  " + banner.paint(f"{g['dot']} Ghidra not found; pseudo-code tab "
                                          "disabled (set --ghidra-home or GHIDRA_HOME)",
                                          banner.MUTED))
            model = report_mod.build_model(engine, p, run_symbolic=run_symbolic,
                                           ghidra_home=gh)
            out = _report_path(report, idx, p)
            report_mod.write_report(out, model)
            print("  " + banner.paint(f"{g['dot']} wrote {out}", banner.CYAN))
        for r in rows:
            r["binary"] = p
            all_rows.append(r)

    if json_out:
        json.dump(all_rows, open(json_out, "w"), indent=2, default=str)
        print(f"\n[+] wrote {json_out}")
    if csv_out:
        cols = ["binary", "arch", "verdict", "cls", "sink", "addr", "function",
                "tainted_arg", "sources", "score", "severity", "path", "evidence"]
        with open(csv_out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in all_rows:
                w.writerow(r)
        print(f"[+] wrote {csv_out}")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="vexhound scan",
        description="Static source-to-sink pipeline with a per-class verdict "
                    "(CONFIRMED / NEEDS_SYMBOLIC / REFUTED) for each candidate.")
    ap.add_argument("targets", nargs="+", help="binaries to analyze")
    ap.add_argument("--json", metavar="FILE", help="write candidates as JSON")
    ap.add_argument("--csv", metavar="FILE", help="write candidates as CSV")
    a = ap.parse_args(argv)
    from . import banner
    banner.set_enabled(banner.stdout_supports_color())
    return run(a.targets, a.json, a.csv)


if __name__ == "__main__":
    sys.exit(main())
