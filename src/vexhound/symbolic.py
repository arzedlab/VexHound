"""
symbolic.py - SYMBOLIC confirmation of a static candidate.

The static stages say "attacker data can reach this sink". Symbolic
execution tries to *prove* it on a feasible path and hand back a concrete trigger.
Because whole-firmware symbolic execution from the network entry is infeasible, we
do TARGETED (function-local) symbolic execution, the standard practical technique:

  1. start a state at the sink's CONTAINING FUNCTION entry,
  2. hook the input primitives (getenv/read/recv/fgets/...) so they return SYMBOLIC
     bytes carrying a taint annotation,
  3. explore toward the sink call address under a time/step budget,
  4. if reached, check whether the tainted ARGUMENT at the sink is derived from
     attacker input (claripy annotation, not a symbolic-ness guess) and solve a
     concrete sample,
  5. report CONFIRMED_SYM (reached + attacker-controlled), REACHED_TAINTED (reached
     on a path that consumed attacker input, but the final arg was concretized),
     REACHED (reached, no attacker input), or UNCONFIRMED (not reached in budget).

This proves intra-function reachability with attacker-controlled data. Full
network-to-sink reachability is the job of the emulation stage.
"""
import logging

logging.disable(logging.CRITICAL)
import sys
import time

import angr
import claripy

from .scan import VexScan

INPUT_PRIMS = ("getenv", "nvram_get", "websGetVar", "sobj_get_string")
READ_PRIMS = ("read", "recv", "recvfrom", "fread")

# Standard libc predicates/transformers angr models accurately. We bind these to
# angr's real SimProcedures instead of collapsing them, so a guard like
# `if (strcmp(field,"admin")) ...` constrains the path the way it does at runtime.
# Collapsing them to an unconstrained value (the old behaviour) made both branches
# look feasible and let the search "reach" sinks down impossible paths.
GUARD_LIBC = ("strcmp", "strncmp", "memcmp", "strlen", "strnlen", "strchr",
              "strrchr", "strstr", "atoi", "strtol", "strtoul", "strncpy",
              "memcpy", "memset")
# angr has no case-insensitive models; approximate with the case-sensitive one,
# which still ties the result to the operands (far better than unconstrained).
GUARD_LIBC_ALIAS = {"strcasecmp": "strcmp", "strncasecmp": "strncmp"}

# Internal SDK/plumbing helpers with real bodies in the binary that only explode
# the path count. Collapse them to a single returned word instead of exploring
# their bodies. The collapse is taint-propagating: if the helper is handed
# attacker data (unescape/dup/getters), its result stays tainted, mirroring how
# the static stage treats an unknown callee (summary.py). Collapsing to a *plain*
# word here is what silently dropped provenance and downgraded real bugs.
COLLAPSE = ("sobj_new", "sobj_add_string", "sobj_add_char", "sobj_free",
            "sobj_del", "sobj_unescape_uri", "sobj_strdup", "sobj_get_int",
            "cgibin_reatwhite", "xmldbc_ephp", "xmldbc_ephp_wb", "xmldbc_del",
            "xmldbc_set", "lockf", "fputs", "fprintf", "fopen", "fclose",
            "unlink", "strdup", "strtok")


class TaintedAnnotation(claripy.Annotation):
    """Marks a symbolic value as attacker-derived. eliminatable=False keeps it
    through simplification; relocatable=True carries it across operations and
    memory. Pattern from PLSysSec/pitchfork-angr."""
    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

    def relocate(self, src, dst):
        anns = [a for a in src.annotations if isinstance(a, TaintedAnnotation)]
        return anns[0] if anns else None


def _is_tainted(ast):
    if ast is None or not isinstance(ast, claripy.ast.Base):
        return False
    if any(isinstance(a, TaintedAnnotation) for a in ast.annotations):
        return True
    try:
        return any(isinstance(a, TaintedAnnotation)
                   for leaf in ast.leaf_asts() for a in leaf.annotations)
    except Exception:
        return False


def _tainted_bytes(state, name, nbytes):
    return state.solver.BVS(name, nbytes * 8, annotations=(TaintedAnnotation(),))


def build_project(path):
    proj = angr.Project(path, auto_load_libs=False)

    class SymRet(angr.SimProcedure):
        """input getter returning a pointer to fresh tainted bytes."""
        def run(self, *a):
            buf = self.state.heap.allocate(0x104)
            self.state.memory.store(buf, _tainted_bytes(self.state, "attacker", 0x100))
            self.state.memory.store(buf + 0x100, claripy.BVV(0, 32))   # null-ish tail
            return buf

    class SymFill(angr.SimProcedure):
        """read/recv/fread: fill the caller buffer (arg1) with tainted bytes."""
        def run(self, a0, a1, a2, *rest):
            n = 0x80
            if not self.state.solver.symbolic(a2):
                n = min(self.state.solver.eval(a2), 0x200) or 0x80
            self.state.memory.store(a1, _tainted_bytes(self.state, "readbuf", n))
            return n

    class SymFgets(angr.SimProcedure):
        """fgets(buf, size, stream): fill buf with tainted bytes, return buf."""
        def run(self, buf, size, stream):
            n = 0x80
            if not self.state.solver.symbolic(size):
                n = min(self.state.solver.eval(size), 0x200) or 0x80
            self.state.memory.store(buf, _tainted_bytes(self.state, "fgets", n))
            return buf

    class TaintProp(angr.SimProcedure):
        """collapse a helper to one returned word, no forking. Taint the result if
        any argument is (or points at) tainted data, so getter/transformer wrappers
        don't drop provenance on the way to the sink."""
        def run(self, a0, a1, a2, a3):
            r = self.state.solver.BVS("ret", self.state.arch.bits)
            for a in (a0, a1, a2, a3):
                if _is_tainted(a):
                    return r.annotate(TaintedAnnotation())
                try:
                    if _is_tainted(self.state.memory.load(a, 8)):
                        return r.annotate(TaintedAnnotation())
                except Exception:
                    pass
            return r

    def hook(nm, proc):
        try:
            proj.hook_symbol(nm, proc)
        except Exception:
            pass

    for nm in INPUT_PRIMS:
        hook(nm, SymRet())
    for nm in READ_PRIMS:
        hook(nm, SymFill())
    hook("fgets", SymFgets())
    for nm in GUARD_LIBC:
        try:
            hook(nm, angr.SIM_PROCEDURES["libc"][nm]())
        except Exception:
            pass
    for nm, real in GUARD_LIBC_ALIAS.items():
        try:
            hook(nm, angr.SIM_PROCEDURES["libc"][real]())
        except Exception:
            pass
    for nm in COLLAPSE:
        hook(nm, TaintProp())
    return proj


def _eval_hex(state, ast, n=16):
    try:
        return state.solver.eval(ast, cast_to=bytes)[:n].hex()
    except Exception:
        return None


def _tainted_sink_arg(st, argregs, bits, tainted_arg):
    """Is any sink argument attacker-derived on this reached state? Returns
    (where, index, witness) or None. "attacker-derived" means the value carries our
    taint annotation, not merely that it is symbolic: after modelling, plenty of
    unrelated values are symbolic. Check the hinted arg first, then the rest."""
    order = ([tainted_arg] if isinstance(tainted_arg, int) else []) + \
            [i for i in range(len(argregs)) if i != tainted_arg]
    for i in order:
        if i >= len(argregs):
            continue
        val = st.registers.load(argregs[i], bits // 8)
        if _is_tainted(val):                    # the argument value itself is attacker data
            return ("reg", i, _eval_hex(st, val))
        try:                                    # or it points at attacker bytes
            mem = st.memory.load(st.solver.eval(val), 32)
            if _is_tainted(mem):
                return ("buf", i, _eval_hex(st, mem))
        except Exception:
            pass
    return None


def confirm(path, func_addr, sink_addr, tainted_arg=None, budget_s=45,
            max_steps=3000, proj=None):
    proj = proj or build_project(path)
    vs = VexScan(path)
    argregs = vs.argregs

    state = proj.factory.call_state(func_addr)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    try:
        state.register_plugin("loop_data", state.loop_data)
    except Exception:
        pass

    simgr = proj.factory.simgr(state)
    try:
        simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=10))
    except Exception:
        pass

    reached = []            # states that hit the sink (harvested, not stopped on)
    consumed_taint = False   # any reached path whose branch conditions ate attacker input
    strong = None            # (state, (where, arg, witness)) with a tainted sink arg

    t0 = time.time()
    steps = 0
    # Don't stop at the FIRST state to hit the sink: it may arrive on a path where
    # the tainted data isn't in the argument. Keep exploring until we find a path
    # whose sink argument is genuinely attacker-derived, or the budget runs out.
    while (simgr.active and strong is None and steps < max_steps
           and time.time() - t0 < budget_s):
        try:
            simgr.step()
        except Exception:
            break                                   # a wild state killed the step: stop
        simgr.move(from_stash="active", to_stash="found",
                   filter_func=lambda s: s.addr == sink_addr)
        for st in simgr.stashes.get("found", []):
            reached.append(st)
            consumed_taint = consumed_taint or any(_is_tainted(c) for c in st.solver.constraints)
            hit = _tainted_sink_arg(st, argregs, vs.bits, tainted_arg)
            if hit is not None:
                strong = (st, hit)
                break
        simgr.stashes["found"] = []
        # when the frontier overflows, keep the states closest to the sink rather
        # than an arbitrary slice, so the budget is spent walking toward it.
        if len(simgr.active) > 400:
            simgr.active.sort(key=lambda s: abs(s.addr - sink_addr))
            simgr.split(from_stash="active", to_stash="deferred", limit=400)
        steps += 1
    dt = time.time() - t0

    if strong is not None:
        _st, (where, i, witness) = strong
        return {"result": "CONFIRMED_SYM", "time": dt, "witness": witness,
                "reason": f"reached {hex(sink_addr)} with arg{i} attacker-controlled "
                f"({'tainted value' if where == 'reg' else 'points at tainted buffer'})"}
    if reached:
        if consumed_taint:
            return {"result": "REACHED_TAINTED", "time": dt,
                    "reason": f"sink {hex(sink_addr)} reached on a path whose branch "
                    "conditions consumed attacker input, but no sink argument was "
                    "provably attacker-derived (intermediate model concretized it); "
                    "reachability holds"}
        return {"result": "REACHED", "time": dt,
                "reason": "sink reached but attacker input not involved on this path"}
    return {"result": "UNCONFIRMED", "reason": f"sink not reached in {dt:.0f}s / "
            f"{steps} steps ({len(simgr.active)} live, "
            f"{len(simgr.stashes.get('errored', []))} errored)", "time": dt}


def batch(path, per_budget=15, only_needs_symbolic=True):
    """Pull rule-stage verdicts and run symbolic confirmation on the survivors."""
    from .rules import RuleEngine
    proj = build_project(path)                 # one hooked project, reused per candidate
    rows = RuleEngine(path).run()
    targets = [r for r in rows if (not only_needs_symbolic or r["verdict"] == "NEEDS_SYMBOLIC")]
    print("=" * 78)
    print("BINARY:", path, f"  ({len(targets)} candidate(s) to symbolically confirm)")
    for r in targets:
        sym = proj.loader.find_symbol(r["function"])
        if sym is None:
            continue
        ta = None
        for tok in r["tainted_arg"].split(","):
            if tok.startswith("arg") and tok[3:].isdigit():
                ta = int(tok[3:]); break
        res = confirm(path, sym.rebased_addr, int(r["addr"], 16), ta,
                      budget_s=per_budget, proj=proj)
        w = f"  witness={res['witness']}" if res.get("witness") else ""
        print(f"  [{res['result']:15}] {r['cls']:8} {r['sink']}@{r['addr']} "
              f"{r['function']}  ({res['time']:.0f}s){w}")
        print(f"        {res['reason']}")


def run(path, func=None, sink=None, arg=None, budget=45):
    """With no func/sink, batch-confirm the NEEDS_SYMBOLIC candidates. With
    both, symbolically confirm one sink call in one function and print the result."""
    if func is None or sink is None:
        batch(path)
        return 0
    print(f"symbolic-confirming sink {hex(sink)} in function {hex(func)} "
          f"(budget {budget}s)")
    r = confirm(path, func, sink, arg, budget_s=budget)
    print(f"  result : {r['result']}   ({r['time']:.0f}s)")
    print(f"  detail : {r['reason']}")
    if r.get("witness"):
        print(f"  witness: attacker input starts {r['witness']} ...")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="vexhound confirm",
        description="Symbolically confirm static candidates (reachability + a trigger).")
    ap.add_argument("target", help="binary to analyze")
    ap.add_argument("--func", type=lambda s: int(s, 0),
                    help="containing function address (omit for batch mode)")
    ap.add_argument("--sink", type=lambda s: int(s, 0), help="sink call address")
    ap.add_argument("--arg", type=int, help="hint: which argument index carries taint")
    ap.add_argument("--budget", type=int, default=45, help="per-target time budget (s)")
    a = ap.parse_args(argv)
    return run(a.target, a.func, a.sink, a.arg, a.budget)


if __name__ == "__main__":
    sys.exit(main())
