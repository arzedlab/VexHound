"""
taint.py: a REAL forward taint-flow pass over angr VEX IR (demonstration).

The static detectors (batch_scan, scan) stop at "unbounded sink +
parsed-input getter present in the SAME function": a presence heuristic, NOT
taint.  This module builds an actual forward data-flow taint analysis over pyvex:

  sources    : calls to parsed-input getters (getenv/sobj_get_string/...), and
               calls whose ARGUMENTS are already tainted (derived flow).  Each
               source call taints the RETURN register with a provenance label.
  memory src : read/recv/fgets/... write attacker bytes -> taint the pointed slot.
  propagate  : per block, statements in order:
                 WrTmp  tainted if expression reads tainted reg/tmp/slot
                 Put    register = data taint            (def kills old)
                 Store  known slot = data taint          (clean store kills)
                 Load   tmp = slot taint
               Across blocks: forward may-analysis, join = union of predecessors,
               iterated to a fixed point over the intra-procedural CFG.
  sink       : at calls to strcpy/sprintf/system/..., if an argument register or
               a reachable memory slot is tainted -> report the label flow.

Flow-sensitive within a block; may-analysis at joins; fully static; nothing runs.
"""
import logging

logging.disable(logging.CRITICAL)
import sys

import pyvex

from .scan import STRONG, UNBOUNDED, VexScan, normf
from .vex import BlockV, scan_function

MEM_READ_SRC = {"read", "recv", "fgets", "fread", "getline"}
F1_SINKS = UNBOUNDED | {"snprintf", "strncpy", "memcpy", "strcat"}
F3_SINKS = {"system", "popen", "execlp", "execl", "execvp", "execve", "snprintf"}
# how many leading args are "data/buffer" vs "size/count": data args are usually all
# but the last two (size). This treats every argument register as a potential data arg.


def slot_of(lin):
    c, coeff, unk, _ = lin
    if unk:
        return None
    if not coeff:
        return ("abs", c)
    if len(coeff) == 1:
        ro = next(iter(coeff))
        return (ro, c)
    return None


class TaintEngine:
    def __init__(self, path, vs=None):
        self.vs = vs or VexScan(path)
        self.arch = self.vs.arch
        self.sp = self.vs.sp
        self.nm2off = self.vs.nm2off
        self.ret = None
        for nm in ("v0", "rax", "r0", "a0", "r3", "eax"):
            if nm in self.nm2off:
                self.ret = self.nm2off[nm][0]
                break
        self.args = self.vs.argregs
        self.SOURCES = set(STRONG)

    # ---------- expression taint ----------
    def expr_taint(self, e, tmp_t, regs, depth=0):
        if depth > 10:
            return frozenset()
        if isinstance(e, pyvex.expr.Const):
            return frozenset()
        if isinstance(e, pyvex.expr.RdTmp):
            return tmp_t.get(e.tmp, frozenset())
        if isinstance(e, pyvex.expr.Get):
            return regs.get(e.offset, frozenset())
        if isinstance(e, pyvex.expr.Load):
            return frozenset()          # memory handled at WrTmp level
        out = set()
        if isinstance(e, (pyvex.expr.Binop, pyvex.expr.Unop)):
            for a in e.args:
                out |= self.expr_taint(a, tmp_t, regs, depth + 1)
        elif isinstance(e, pyvex.expr.ITE):
            out |= self.expr_taint(e.cond, tmp_t, regs, depth + 1)
            out |= self.expr_taint(e.iffalse, tmp_t, regs, depth + 1)
            out |= self.expr_taint(e.iftrue, tmp_t, regs, depth + 1)
        return frozenset(out)

    # ---------- block transfer : in -> out ----------
    def transfer(self, ba, irsb, bv, in_regs, in_mem, srcs_at):
        """returns (out_regs, out_mem, sinks) with def-kill semantics."""
        regs = {k: set(v) for k, v in in_regs.items()}
        mem = {k: set(v) for k, v in in_mem.items()}
        tmp_t = {}
        sinks = []                       # (nm, labelset)
        arg_slots = {}                   # arg reg -> frame/abs slot (last value)
        for i, st in enumerate(irsb.statements):
            if isinstance(st, pyvex.stmt.WrTmp):
                d = st.data
                t = set()
                if isinstance(d, pyvex.expr.Load):
                    ac, aco, aun, afr = bv.rhs_linear(d.addr, i)
                    s = slot_of((ac, aco, aun, afr))
                    if s is not None:
                        t |= mem.get(s, set())
                    # a tainted base pointer makes this an arbitrary read
                    pt = self.expr_taint(d.addr, tmp_t, regs)
                    if pt:
                        t |= pt
                else:
                    t = set(self.expr_taint(d, tmp_t, regs))
                if t:
                    tmp_t[st.tmp] = frozenset(t)
            elif isinstance(st, pyvex.stmt.Put):
                t = set(self.expr_taint(st.data, tmp_t, regs))
                if t:
                    regs[st.offset] = t
                else:
                    regs.pop(st.offset, None)
                if st.offset in self.args:
                    ac, aco, aun, afr = bv.rhs_linear(st.data, i)
                    s = slot_of((ac, aco, aun, afr))
                    arg_slots[st.offset] = s
            elif isinstance(st, pyvex.stmt.Store):
                ac, aco, aun, afr = bv.rhs_linear(st.addr, i)
                s = slot_of((ac, aco, aun, afr))
                dt = set(self.expr_taint(st.data, tmp_t, regs))
                if s is not None:
                    if dt:
                        mem[s] = mem.get(s, set()) | dt
                    else:
                        mem.pop(s, None)
                else:
                    at = set(self.expr_taint(st.addr, tmp_t, regs))
                    if at or dt:
                        mem[("any",)] = mem.get(("any",), set()) | at | dt
        # call handling: this IRSB is a call if jumpkind Ijk_Call
        if str(irsb.jumpkind).startswith("Ijk_Call"):
            nm = srcs_at.get(ba)
            # taint of the memory a pointer arg may point to, plus arg regs
            labels = set()
            for ro in self.args:
                labels |= regs.get(ro, set())
            for (sl, tv) in list(mem.items()):
                labels |= tv
            # memory-reading sources write attacker bytes into their buffer arg
            if nm in MEM_READ_SRC:
                mem[("any",)] = mem.get(("any",), set()) | {nm}
            if nm in self.SOURCES:
                labels |= {nm} if nm else set()
            # derived flow: tainted argument => return tainted
            ret_t = set()
            arg_tainted = any(regs.get(ro, set()) for ro in self.args)
            if nm and nm in self.SOURCES:
                ret_t |= {normf(nm)}
            if arg_tainted:
                for ro in self.args:
                    ret_t |= regs.get(ro, set())
            if self.ret is not None and ret_t:
                regs[self.ret] = regs.get(self.ret, set()) | ret_t
            # sink test: tainted arg register, OR arg points at a tainted slot
            if nm in F1_SINKS or nm in F3_SINKS:
                sink_lab = set()
                for ro in self.args:
                    sink_lab |= regs.get(ro, set())
                    s = arg_slots.get(ro)
                    if s is not None:
                        sink_lab |= mem.get(s, set())
                # also whole-memory taint (pointer may target anything)
                sink_lab |= mem.get(("any",), set())
                if sink_lab:
                    sinks.append((nm, frozenset(sink_lab)))
        return regs, mem, sinks

    # ---------- whole-function forward may-analysis ----------
    def run_function(self, name, addr, fsize):
        blocks = self.vs.function_blocks(addr, fsize)
        if not blocks:
            return [], {}
        prologue = min(blocks)
        facts = scan_function(self.vs, name, addr, fsize)
        srcs_at = {cba: cnm for (cba, cnm) in facts["calls"]}

        def succ(ba):
            out = set()
            try:
                nxt = self.vs.proj.factory.block(ba).vex.next
            except Exception:
                nxt = None
            if isinstance(nxt, pyvex.expr.Const) and nxt.con.value in blocks:
                out.add(nxt.con.value)
            hi = [b for b in blocks if b > ba]
            if hi:
                out.add(min(hi))
            try:                                 # conditional/backward branch targets
                for st in self.vs.proj.factory.block(ba).vex.statements:
                    if isinstance(st, pyvex.stmt.Exit) and st.dst.value in blocks:
                        out.add(st.dst.value)
            except Exception:
                pass
            return out

        pred = {b: set() for b in blocks}
        for b in blocks:
            for s in succ(b):
                pred.setdefault(s, set()).add(b)
        # lattice state per block
        OUT = {b: ({}, {}) for b in blocks}
        IN = {b: ({}, {}) for b in blocks}

        def join(b):
            jr, jm = {}, {}
            for p in pred.get(b, []) or []:
                r, m = OUT.get(p, ({}, {}))
                for k, v in r.items():
                    if k in jr:
                        jr[k] |= set(v)
                    else:
                        jr[k] = set(v)
                for k, v in m.items():
                    if k in jm:
                        jm[k] |= set(v)
                    else:
                        jm[k] = set(v)
            return jr, jm

        def equal(a, b):
            return all(set(a[0].get(k, [])) == set(b[0].get(k, [])) and
                       set(a[1].get(k, [])) == set(b[1].get(k, []))
                       for k in set(a[0]) | set(b[0]) | set(a[1]) | set(b[1]))

        all_sinks = []
        for it in range(25):
            changed = False
            for b in sorted(blocks):
                IN[b] = join(b)
                try:
                    irsb = self.vs.proj.factory.block(b).vex
                except Exception:
                    continue
                cp = (b == prologue)
                bv = BlockV(irsb, self.sp, self.vs.bits, 0, cp)
                r, m, sinks = self.transfer(b, irsb, bv,
                                            IN[b][0], IN[b][1], srcs_at)
                for (nm, lab) in sinks:
                    all_sinks.append((b, nm, lab))
                new = (r, m)
                if not equal(new, OUT[b]):
                    OUT[b] = new
                    changed = True
            if not changed:
                break
        # dedupe sink hits from the final lattice
        seen = set()
        final = []
        # replay on final IN to avoid duplicates from earlier iterations
        for b in sorted(blocks):
            try:
                irsb = self.vs.proj.factory.block(b).vex
            except Exception:
                continue
            cp = (b == prologue)
            bv = BlockV(irsb, self.sp, self.vs.bits, 0, cp)
            r, m, sinks = self.transfer(b, irsb, bv, IN[b][0], IN[b][1],
                                        srcs_at)
            for (nm, lab) in sinks:
                key = (b, nm, frozenset(lab))
                if key not in seen:
                    seen.add(key)
                    final.append(key)
        return final, {"regs": OUT, "mem": OUT}


def main():
    for p in sys.argv[1:]:
        print("=" * 80)
        print("BINARY:", p)
        eng = TaintEngine(p)
        vs = eng.vs
        funcs = []
        for s in vs.mo.symbols:
            if s.name and not s.is_import and "STT_FUNC" in str(getattr(s, "subtype", "")):
                try:
                    a0 = s.rebased_addr
                except Exception:
                    continue
                if a0 and a0 >= vs.mo.min_addr and (getattr(s, "size", 0) or 0) < 0x6000:
                    nm = normf(s.name)
                    is_h = nm.endswith(("cgi_main", "_main")) or nm in ("main", "hnap_main") or nm == "main"
                    if is_h and nm and not nm.startswith("_"):
                        funcs.append((s.name, a0, getattr(s, "size", 0) or 0))
        for (nm, a0, sz) in funcs:
            try:
                hits, _ = eng.run_function(nm, a0, sz)
            except Exception as e:
                print(f"  {nm}: error {type(e).__name__} {str(e)[:90]}")
                continue
            if hits:
                print(f"  -- {nm}@{a0:#x}: {len(hits)} taint-reached sink(s)")
                for (ba, sink, lab) in sorted(hits):
                    print(f"       flow: {sorted(lab)} -> {sink}   (call block {ba:#x})")


if __name__ == "__main__":
    main()
