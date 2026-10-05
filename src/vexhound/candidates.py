"""
candidates.py - turn summary.py's raw inter-procedural taint
FLOWS into a clean, DEDUPLICATED, RANKED candidate list for the later rule and
symbolic stages.

Each candidate carries:
  bug_class        overflow / cmdi / fmt / alloc / uaf
  sink             the dangerous primitive and its call address + containing function
  tainted_arg      which argument index at the sink carried attacker taint
  sources          the input primitives / source functions feeding it
  path             the call-graph path from an entry handler down to the sink function
  reachable        whether the sink function is reachable from an entry handler
  score / severity a triage priority so the expensive later stages go first
  confidence       'flow' for spatial classes, 'candidate' for temporal (uaf/alloc)

Consumes summary.SummaryEngine. Static only; nothing is executed.
"""
import logging

logging.disable(logging.CRITICAL)
import csv
import itertools
import json
import sys

try:
    import networkx as nx
except Exception:
    nx = None

from .summary import SummaryEngine

# ---- ranking knobs (a defensible starter formula; tune later) -----------------
CLASS_W = {"overflow": 5, "cmdi": 5, "fmt": 3, "alloc": 2, "uaf": 2}
UNBOUNDED = {"strcpy", "strcat", "sprintf", "stpcpy", "vsprintf", "gets",
             "system", "popen", "execl", "execlp", "execv", "execve", "execvp"}
NET_SRC = {"getenv", "recv", "recvfrom", "read", "websGetVar", "nvram_get"}
FILE_SRC = {"fread", "fgets", "getline"}
TEMPORAL = {"uaf", "alloc"}


def _is_entry(name):
    return name == "main" or name.endswith(("_main", "cgi_main"))


def _severity(score):
    if score >= 10:
        return "CRITICAL"
    if score >= 8:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"


class CandidateBuilder:
    def __init__(self, path, vs=None):
        self.eng = SummaryEngine(path, vs=vs)
        self.eng.compute_all()                       # summary stage
        self.arch = self.eng.vs.arch.name
        self._build_callgraph()

    # ---- call graph over internal functions, with a synthetic ENTRY node -----
    def _build_callgraph(self):
        self.g = nx.DiGraph() if nx else None
        self.entries = [a for a, (nm, _s) in self.eng.funcs.items() if _is_entry(nm)]
        if self.g is None:
            return
        for a in self.eng.funcs:
            self.g.add_node(a)
        for a in self.eng.funcs:
            for nm in (self.eng._srcs_at.get(a) or {}).values():
                c = self.eng.name2addr.get(nm)
                if c is not None and c != a:
                    self.g.add_edge(a, c)
        self.g.add_node("ENTRY")
        for e in self.entries:
            self.g.add_edge("ENTRY", e)

    def _path_to(self, func_addr):
        """function-name call path from an entry handler down to func_addr."""
        if self.g is None or func_addr not in self.eng.funcs:
            return [self.eng.funcs.get(func_addr, ("?",))[0]], False
        try:
            p = nx.shortest_path(self.g, "ENTRY", func_addr)[1:]   # drop synthetic node
            return [self.eng.funcs[a][0] for a in p], True
        except Exception:
            return [self.eng.funcs[func_addr][0]], False

    def _paths_to(self, func_addr, k=3):
        """Up to k DISTINCT entry->func_addr call chains (function-name lists),
        shortest first. This is the bounded call-graph enumeration behind the
        report's "also reachable from ..." hint: a sink function is often reachable
        from more than one attacker-facing handler, and showing the alternatives
        aids triage. _path_to stays the single shortest chain for the primary view.

        Bounded deliberately so the call graph's branching cannot explode: only
        simple paths (no repeated function) within a small length cutoff are taken,
        the DFS enumeration is hard-capped, and at most k chains are returned. We do
        NOT enumerate all paths (that is intractable in general and adds no verdict
        value); this is an explainability aid over the small function-level graph."""
        if self.g is None or nx is None or func_addr not in self.eng.funcs:
            return [[self.eng.funcs.get(func_addr, ("?",))[0]]], False
        try:
            sp = nx.shortest_path(self.g, "ENTRY", func_addr)[1:]   # drop synthetic
        except Exception:
            return [[self.eng.funcs[func_addr][0]]], False
        short = [self.eng.funcs[a][0] for a in sp]
        cutoff = max(len(sp) + 2, 5)                # don't wander far past the shortest
        seen, alts = {tuple(short)}, []
        try:
            gen = nx.all_simple_paths(self.g, "ENTRY", func_addr, cutoff=cutoff)
            for p in itertools.islice(gen, 300):   # hard cap on enumeration work
                names = tuple(self.eng.funcs[a][0] for a in p[1:])
                if names in seen:
                    continue
                seen.add(names)
                alts.append(list(names))
        except Exception:
            pass
        alts.sort(key=len)
        return [short] + alts[:max(0, k - 1)], True

    # ---- compose + dedupe + rank --------------------------------------------
    def build(self):
        merged = {}                                  # (cls, func, sink, at) -> candidate
        for fl in self.eng.flows:
            key = (fl["cls"], fl["func"], fl["sink"], fl["at"])
            c = merged.get(key)
            if c is None:
                c = {"cls": fl["cls"], "func": fl["func"], "sink": fl["sink"],
                     "at": fl["at"], "sources": set(), "args": set()}
                merged[key] = c
            c["sources"].add(fl["source"])
            if fl.get("arg") is not None:
                c["args"].add(fl["arg"])

        cands = []
        for c in merged.values():
            fname = self.eng.funcs.get(c["func"], ("?",))[0]
            path, reachable = self._path_to(c["func"])
            srcs = c["sources"]
            score = CLASS_W.get(c["cls"], 1)
            if c["sink"] in UNBOUNDED:
                score += 2
            if srcs & NET_SRC:
                score += 2
            elif srcs & FILE_SRC:
                score += 1
            else:
                score += 2                          # derived internal source: request-carried
            if reachable:
                score += 2
            cands.append({
                "cls": c["cls"], "function": fname, "sink": c["sink"],
                "addr": hex(c["at"]),
                "tainted_arg": ",".join(f"arg{i}" for i in sorted(c["args"])) or "?",
                "sources": ",".join(sorted(srcs)),
                "path": " -> ".join(path),
                "reachable": reachable,
                "score": score, "severity": _severity(score),
                "confidence": "candidate" if c["cls"] in TEMPORAL else "flow",
            })
        cands.sort(key=lambda x: (-x["score"], x["cls"], x["function"]))
        for i, c in enumerate(cands, 1):
            c["rank"] = i
        return cands


def main():
    args = list(sys.argv[1:])
    json_out = csv_out = None
    if "--json" in args:
        i = args.index("--json"); json_out = args[i + 1]; del args[i:i + 2]
    if "--csv" in args:
        i = args.index("--csv"); csv_out = args[i + 1]; del args[i:i + 2]

    all_rows = []
    for p in args:
        print("=" * 78)
        print("BINARY:", p)
        cb = CandidateBuilder(p)
        cands = cb.build()
        print(f"  arch: {cb.arch}   ranked candidates: {len(cands)}\n")
        for c in cands:
            print(f"  #{c['rank']:<2} [{c['severity']:8} {c['score']:2}] {c['cls']:8} "
                  f"{c['sink']}@{c['addr']}  ({c['confidence']})")
            print(f"       function : {c['function']}   tainted: {c['tainted_arg']}")
            print(f"       sources  : {c['sources']}")
            print(f"       path     : {c['path']}" +
                  ("" if c["reachable"] else "   [not reachable from an entry handler]"))
        for c in cands:
            c["binary"] = p
            c["arch"] = cb.arch
            all_rows.append(c)

    if json_out:
        json.dump(all_rows, open(json_out, "w"), indent=2)
        print(f"\n[+] wrote {json_out} ({len(all_rows)} candidates)")
    if csv_out:
        cols = ["binary", "arch", "rank", "score", "severity", "cls", "confidence",
                "function", "sink", "addr", "tainted_arg", "sources", "reachable", "path"]
        with open(csv_out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for c in all_rows:
                w.writerow(c)
        print(f"[+] wrote {csv_out} ({len(all_rows)} candidates)")


if __name__ == "__main__":
    main()
