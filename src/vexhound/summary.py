"""
summary.py - AUTOMATIC function classification
plus INTER-PROCEDURAL taint, both computed from angr VEX IR.

Idea
----
Instead of hand-listing which functions are sources/sinks (the scattered sets in
scan.py / taint.py), we infer a ROLE for every function that
has a body, by computing a per-function SUMMARY and propagating it across the call
graph bottom-up (callees before callers). Only the irreducible libc primitives
(the externs with no body) are modeled by a tiny axiom seed.

Per function we compute:
  param_to_sink[i] : set of (bug_class, primitive) that parameter i can reach
  param_to_ret     : set of parameter indices whose taint flows to the return
  src_output       : True if the return carries attacker-derived (input) taint
and from those, a ROLE:
  SOURCE     - returns attacker-derived data                 (src_output)
  SINK[cls]  - a parameter reaches a dangerous primitive     (param_to_sink)
  PROPAGATOR - a parameter flows to the return, nothing worse (param_to_ret)
  NEUTRAL    - none of the above

Inter-procedural taint falls out of the same machinery: when a SOURCE's tainted
output later reaches a sink (directly or through a callee summary), we record a
FLOW candidate (the source -> sink chains that Parts 2/3 consume).

Reuses: VexScan (loader/names/argregs), TaintEngine.expr_taint + slot_of
(taint.py), BlockV/scan_function (vex.py). Nothing is executed.
"""
import logging

logging.disable(logging.CRITICAL)
import sys

import pyvex

try:
    import networkx as nx
except Exception:
    nx = None

from .scan import STRONG, normf
from .taint import TaintEngine, slot_of
from .vex import BlockV, scan_function

# ---- axiom seed: the ONLY hand-specified knowledge (irreducible primitives) ----
# input primitives: taint the return and/or a buffer argument
SOURCE_PRIM = {
    "getenv": {"ret": True}, "nvram_get": {"ret": True}, "nvram_bufget": {"ret": True},
    "httpGetEnv": {"ret": True}, "http_get_env": {"ret": True}, "httpGetValue": {"ret": True},
    "websGetVar": {"ret": True}, "sobj_get_string_raw": {"ret": True},
    "read": {"buf": 1}, "recv": {"buf": 1}, "recvfrom": {"buf": 1},
    "fread": {"buf": 0}, "fgets": {"buf": 0, "ret": True}, "getline": {"buf": 0},
}
# dangerous primitives: (bug_class, tuple of argument indices worth watching for taint)
SINK_PRIM = {
    "strcpy": ("overflow", (1,)), "strcat": ("overflow", (1,)), "stpcpy": ("overflow", (1,)),
    "memcpy": ("overflow", (1, 2)), "memmove": ("overflow", (1, 2)),
    "sprintf": ("overflow", (1, 2, 3)), "vsprintf": ("overflow", (1, 2)),
    "snprintf": ("overflow", (3, 4)),
    "system": ("cmdi", (0,)), "popen": ("cmdi", (0,)),
    "execl": ("cmdi", (0,)), "execlp": ("cmdi", (0,)), "execv": ("cmdi", (0,)),
    "execve": ("cmdi", (0,)), "execvp": ("cmdi", (0,)),
    "printf": ("fmt", (0, 1, 2)), "fprintf": ("fmt", (1, 2)),
    "malloc": ("alloc", (0,)), "calloc": ("alloc", (0, 1)), "realloc": ("alloc", (1,)),
    "free": ("uaf", (0,)),
}
# copy/format primitives ALSO move taint from source args into their dest buffer,
# so taint survives through a wrapper (sprintf(buf,...); strcpy(dst,buf)).
# name -> (dest_arg_index, tuple of source arg indices)
COPY_PRIM = {
    "strcpy": (0, (1,)), "strcat": (0, (1,)), "stpcpy": (0, (1,)),
    "memcpy": (0, (1,)), "memmove": (0, (1,)),
    "sprintf": (0, (1, 2, 3)), "vsprintf": (0, (1,)),
    "snprintf": (0, (3, 4)), "vsnprintf": (0, (2,)),
}


class Summary:
    """What a function does to its parameters, for the classifier."""
    def __init__(self):
        self.param_to_sink = {}     # param index -> set((bug_class, primitive))
        self.param_to_ret = set()   # param indices whose taint reaches the return
        self.src_output = False     # return / out-param carries attacker taint
        self.reads_input = False    # directly calls an input primitive (getenv/read/...)
        self.role = "NEUTRAL"

    def key(self):
        return (tuple(sorted((i, tuple(sorted(v))) for i, v in self.param_to_sink.items())),
                tuple(sorted(self.param_to_ret)), self.src_output)


class SummaryEngine:
    def __init__(self, path, vs=None):
        self.te = TaintEngine(path, vs=vs)      # reuse loader + expr_taint
        self.vs = self.te.vs
        self.proj = self.vs.proj
        self.sp = self.vs.sp
        self.bits = self.vs.bits
        self.args = list(self.te.args)          # argument register offsets, in order
        self.ret = self.te.ret                  # return-value register offset
        self.summaries = {}                     # func addr -> Summary
        self.flows = []                         # inter-procedural source->sink candidates
        self._inventory()

    # ---- function inventory + name<->addr maps -------------------------------
    def _inventory(self):
        self.funcs = {}                         # addr -> (name, span)
        self.name2addr = {}
        for nm, a, span in self.vs.functions():  # CFG-driven: symbolized + anonymous
            self.funcs[a] = (nm, span)
            self.name2addr.setdefault(nm, a)

    # ---- call graph over internal functions (for bottom-up ordering) ---------
    def _call_targets(self, addr, size):
        """internal callee addresses + resolved callee names per call block."""
        facts = scan_function(self.vs, self.funcs[addr][0], addr, size)
        srcs_at = {}
        callee_addrs = set()
        for (cba, cnm) in facts["calls"]:
            if not cnm:
                continue
            nm = normf(cnm)
            srcs_at[cba] = nm
            if nm in self.name2addr:
                callee_addrs.add(self.name2addr[nm])
        return srcs_at, callee_addrs

    def _ordering(self):
        """SCC condensation, reverse topological (callees before callers)."""
        self._srcs_at = {}
        g = nx.DiGraph() if nx else None
        for a in self.funcs:
            if g is not None:
                g.add_node(a)
            srcs_at, callees = self._call_targets(a, self.funcs[a][1])
            self._srcs_at[a] = srcs_at
            if g is not None:
                for c in callees:
                    if c != a:
                        g.add_edge(a, c)
        if g is None:                           # networkx missing: arbitrary order
            return [[a] for a in self.funcs]
        cond = nx.condensation(g)
        order = list(nx.topological_sort(cond))          # callers ... callees
        order.reverse()                                  # callees first
        return [list(cond.nodes[n]["members"]) for n in order]

    # ---- one forward may-analysis pass over a function -----------------------
    def analyze_function(self, addr):
        _name, size = self.funcs[addr]
        self._cur_func = addr
        srcs_at = self._srcs_at.get(addr) or self._call_targets(addr, size)[0]
        blocks = self.vs.function_blocks(addr, size)
        if not blocks:
            return Summary(), []
        prologue = min(blocks)

        def succ(ba):
            out = set()
            try:
                nxt = self.proj.factory.block(ba).vex.next
            except Exception:
                nxt = None
            if isinstance(nxt, pyvex.expr.Const) and nxt.con.value in blocks:
                out.add(nxt.con.value)
            hi = [b for b in blocks if b > ba]
            if hi:
                out.add(min(hi))
            try:                                 # conditional/backward branch targets
                for st in self.proj.factory.block(ba).vex.statements:
                    if isinstance(st, pyvex.stmt.Exit) and st.dst.value in blocks:
                        out.add(st.dst.value)
            except Exception:
                pass
            return out

        pred = {b: set() for b in blocks}
        for b in blocks:
            for s in succ(b):
                pred.setdefault(s, set()).add(b)

        # entry state: each parameter register carries its own label
        entry_regs = {self.args[i]: {("param", i)} for i in range(len(self.args))}
        OUT = {b: ({}, {}) for b in blocks}
        IN = {b: ({}, {}) for b in blocks}

        def join(b):
            jr, jm = {}, {}
            if b == prologue:
                for k, v in entry_regs.items():
                    jr[k] = set(v)
            for p in pred.get(b, ()):
                r, m = OUT[p]
                for k, v in r.items():
                    jr[k] = jr.get(k, set()) | set(v)
                for k, v in m.items():
                    jm[k] = jm.get(k, set()) | set(v)
            return jr, jm

        events = []
        for _ in range(25):
            changed = False
            events = []
            for b in sorted(blocks):
                IN[b] = join(b)
                try:
                    irsb = self.proj.factory.block(b).vex
                except Exception:
                    continue
                bv = BlockV(irsb, self.sp, self.bits, 0, b == prologue)
                r, m, evs = self._transfer(b, irsb, bv, IN[b][0], IN[b][1], srcs_at)
                events.extend(evs)
                if (r, m) != OUT[b]:
                    OUT[b] = (r, m)
                    changed = True
            if not changed:
                break

        # build this function's summary from the fixpoint. param_to_ret uses a
        # union over all blocks (a may-analysis: we WANT taint to propagate, and
        # the intra-function CFG here is approximate). The SOURCE role is driven
        # by reads_input below, so this union does not mislabel handlers.
        summ = Summary()
        ret_taint = set()
        if self.ret is not None:
            for b in blocks:
                ret_taint |= OUT[b][0].get(self.ret, set())
        for lab in ret_taint:
            if lab[0] == "param":
                summ.param_to_ret.add(lab[1])
            elif lab[0] == "src":
                summ.src_output = True
        for ev in events:
            for lab in ev["labels"]:
                if lab[0] == "param":
                    summ.param_to_sink.setdefault(lab[1], set()).add((ev["cls"], ev["prim"]))
        summ.reads_input = any(nm in SOURCE_PRIM for nm in srcs_at.values())
        return summ, events

    # ---- block transfer with axiom / summary application at calls ------------
    def _transfer(self, ba, irsb, bv, in_regs, in_mem, srcs_at):
        regs = {k: set(v) for k, v in in_regs.items()}
        mem = {k: set(v) for k, v in in_mem.items()}
        tmp_t = {}
        arg_slots = {}
        events = []
        et = self.te.expr_taint
        for i, st in enumerate(irsb.statements):
            if isinstance(st, pyvex.stmt.WrTmp):
                d = st.data
                t = set()
                if isinstance(d, pyvex.expr.Load):
                    s = slot_of(bv.rhs_linear(d.addr, i))
                    if s is not None:
                        t |= mem.get(s, set())
                    t |= et(d.addr, tmp_t, regs)
                else:
                    t = set(et(d, tmp_t, regs))
                if t:
                    tmp_t[st.tmp] = frozenset(t)
            elif isinstance(st, pyvex.stmt.Put):
                t = set(et(st.data, tmp_t, regs))
                if t:
                    regs[st.offset] = t
                else:
                    regs.pop(st.offset, None)
                if st.offset in self.args:
                    arg_slots[st.offset] = slot_of(bv.rhs_linear(st.data, i))
            elif isinstance(st, pyvex.stmt.Store):
                s = slot_of(bv.rhs_linear(st.addr, i))
                dt = set(et(st.data, tmp_t, regs))
                if s is not None:
                    if dt:
                        mem[s] = mem.get(s, set()) | dt
                    else:
                        mem.pop(s, None)
                elif dt or et(st.addr, tmp_t, regs):
                    mem[("any",)] = mem.get(("any",), set()) | dt | set(et(st.addr, tmp_t, regs))

        if not str(irsb.jumpkind).startswith("Ijk_Call"):
            return regs, mem, events
        nm = srcs_at.get(ba)
        anymem = mem.get(("any",), set())

        def arg_taint(idx):
            if idx >= len(self.args):
                return set()
            ro = self.args[idx]
            lab = set(regs.get(ro, set()))
            s = arg_slots.get(ro)
            if s is not None:
                lab |= mem.get(s, set())
            return lab | anymem

        def emit(cls, prim, labels, arg=None):
            if labels:
                events.append({"call": ba, "prim": prim, "cls": cls,
                               "labels": frozenset(labels), "arg": arg})
                for lab in labels:
                    if lab[0] == "src":
                        self.flows.append({"func": self._cur_func, "source": lab[1],
                                           "sink": prim, "cls": cls, "at": ba, "arg": arg})

        ret_labels = set()
        # 1) axiom source primitive
        if nm in SOURCE_PRIM:
            spec = SOURCE_PRIM[nm]
            if spec.get("ret"):
                ret_labels.add(("src", nm))
            if "buf" in spec:
                bi = spec["buf"]
                s = arg_slots.get(self.args[bi]) if bi < len(self.args) else None
                if s is not None:
                    mem[s] = mem.get(s, set()) | {("src", nm)}
                else:
                    mem[("any",)] = mem.get(("any",), set()) | {("src", nm)}
        # 2) axiom sink primitive
        if nm in SINK_PRIM:
            cls, watch = SINK_PRIM[nm]
            for idx in watch:
                emit(cls, nm, arg_taint(idx), idx)
        # 2b) copy/format primitive also moves taint into its destination buffer
        if nm in COPY_PRIM:
            dest_i, src_idxs = COPY_PRIM[nm]
            srctaint = set()
            for si in src_idxs:
                srctaint |= arg_taint(si)
            if srctaint and dest_i < len(self.args):
                s = arg_slots.get(self.args[dest_i])
                if s is not None:
                    mem[s] = mem.get(s, set()) | srctaint
                else:
                    mem[("any",)] = mem.get(("any",), set()) | srctaint
        # 3) internal callee with a computed summary
        callee = self.name2addr.get(nm) if nm else None
        if callee is not None and callee in self.summaries:
            S = self.summaries[callee]
            for j, sinks in S.param_to_sink.items():
                labels = arg_taint(j)
                for (cls, prim) in sinks:
                    emit(cls, prim, labels, j)
            for j in S.param_to_ret:
                ret_labels |= arg_taint(j)
            if S.src_output:
                ret_labels.add(("src", nm))
        # 4) unknown callee: conservative pass-through arg taint to return
        elif nm and nm not in SOURCE_PRIM and nm not in SINK_PRIM:
            for j in range(len(self.args)):
                ret_labels |= arg_taint(j)

        if self.ret is not None and ret_labels:
            regs[self.ret] = regs.get(self.ret, set()) | ret_labels
        # arg registers are caller-saved: drop them after the call
        for ro in self.args:
            regs.pop(ro, None)
        return regs, mem, events

    # ---- drive the whole binary ---------------------------------------------
    def compute_all(self):
        for scc in self._ordering():
            for _ in range(4):                  # fixpoint within a recursive SCC
                stable = True
                for a in scc:
                    old = self.summaries.get(a)
                    summ, _ = self.analyze_function(a)
                    self.summaries[a] = summ
                    if old is None or old.key() != summ.key():
                        stable = False
                if stable:
                    break
        self._classify()

    def _classify(self):
        for S in self.summaries.values():
            classes = sorted({cls for sinks in S.param_to_sink.values() for (cls, _) in sinks})
            if classes:
                S.role = "SINK[" + ",".join(classes) + "]"
            elif S.reads_input:
                S.role = "SOURCE"
            elif S.param_to_ret:
                S.role = "PROPAGATOR"
            else:
                S.role = "NEUTRAL"


def run(paths):
    """Classify every function with a body (SOURCE / SINK / PROPAGATOR / NEUTRAL)
    and print the inter-procedural source-to-sink flow candidates."""
    import os

    from . import banner
    role_color = {"SOURCE": banner.CYAN, "SINK": banner.RED,
                  "PROPAGATOR": banner.AMBER, "NEUTRAL": banner.MUTED}
    for p in paths:
        print(banner.rule(os.path.basename(p)))
        eng = SummaryEngine(p)
        eng.compute_all()

        roles = {}
        for a, S in eng.summaries.items():
            roles.setdefault(S.role.split("[")[0], []).append(eng.funcs[a][0])

        print("  " + banner.paint(f"{len(eng.summaries)} functions classified",
                                  banner.CREAM, bold=True))
        for kind in ("SOURCE", "SINK", "PROPAGATOR", "NEUTRAL"):
            names = sorted(n for r, ns in roles.items() if r == kind for n in ns)
            print("  " + banner.paint(f"{kind:<10}", role_color[kind], bold=(kind in ("SOURCE", "SINK")))
                  + banner.paint(f"{len(names):>3}  ", banner.MUTED)
                  + banner.paint(", ".join(names[:12]) + (" ..." if len(names) > 12 else ""),
                                 banner.MUTED))

        # detail: the SOURCE and SINK functions (the useful ones)
        print("\nSOURCE functions (return attacker-derived data):")
        for a, S in sorted(eng.summaries.items()):
            if S.role == "SOURCE":
                print(f"   {eng.funcs[a][0]:24} @ {a:#x}")
        print("\nSINK functions (a parameter reaches a dangerous primitive):")
        for a, S in sorted(eng.summaries.items()):
            if S.role.startswith("SINK"):
                det = "; ".join(f"param{i}->{','.join(p for _, p in sorted(v))}"
                                for i, v in sorted(S.param_to_sink.items()))
                print(f"   {eng.funcs[a][0]:24} {S.role:22} {det}")

        # inter-procedural flow candidates (source -> sink)
        seen = set()
        uniq = []
        for fl in eng.flows:
            k = (fl["func"], fl["source"], fl["sink"], fl["cls"])
            if k not in seen:
                seen.add(k)
                uniq.append(fl)
        print(f"\ninter-procedural FLOW candidates (source -> sink): {len(uniq)}")
        for fl in uniq[:25]:
            fn = eng.funcs.get(fl["func"], ("?",))[0]
            print(f"   [{fl['cls']:9}] {fl['source']} -> {fl['sink']}   in {fn} @ {fl['at']:#x}")

        # oracle check vs the old hand-curated STRONG source list
        inferred_src = {eng.funcs[a][0] for a, S in eng.summaries.items() if S.role == "SOURCE"}
        hit = sorted(inferred_src & set(STRONG))
        print(f"\noracle: inferred SOURCEs that were in the old hand list STRONG: {hit}")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="vexhound classify",
        description="Automatically classify functions and extract source-to-sink flows.")
    ap.add_argument("targets", nargs="+", help="binaries to analyze")
    a = ap.parse_args(argv)
    from . import banner
    banner.set_enabled(banner.stdout_supports_color())
    return run(a.targets)


if __name__ == "__main__":
    sys.exit(main())
