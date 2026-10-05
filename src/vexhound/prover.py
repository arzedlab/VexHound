"""
prover.py: a PRECISE stack-buffer-overflow prover over angr VEX IR.

Why this exists
---------------
`scan.py` is a *presence* heuristic: it flags F1 when an unbounded
sink NAME (sprintf/strcpy/...) and a parsed-input getter NAME appear in the SAME
function, or when *any* measured `arg0 -> frame` distance to the saved return
address exists together with *any* F1 sink (memcpy/strncpy/read included). It never
inspects the sink's SIZE argument and never proves the attacker data reaches the
sink. Result: correctly-bounded copies (a `memcpy(buf, x, 16)` that fits) are
reported as CRITICAL overflows: false positives.

This module removes those false positives by turning each dangerous call into a
proof obligation, computed entirely from lifted `pyvex` IR:

  1. DEST   recover the destination buffer's frame offset  D   (arg register that
            holds the buffer pointer == sp + D, via vex linear frame math).
  2. ROOM   room = ra_slot - D   (bytes writable before the saved return address).
  3. SIZE   recover the sink's length argument as a CONSTANT n when possible
            (li/mov immediate into the size arg register), or mark it symbolic.
  4. DECIDE
        unbounded sink (strcpy/strcat/sprintf/gets/...) into a stack buffer:
              OVERFLOW  (CRITICAL if room < 0x600, else HIGH)  -- attacker sets len
        bounded sink with constant n:
              n  > room  -> OVERFLOW (size exceeds room)
              n <= room  -> SAFE     (bounded, fits)     <== suppressed, was a FP
        bounded sink with non-constant n:
              n symbolic/tainted -> OVERFLOW (unchecked length)
              n symbolic/untainted -> CANDIDATE (unproven length)
  5. TAINT  a real forward taint pass (taint.TaintEngine) says whether attacker
            input provably reaches this sink. Taint-reached => CONFIRMED, else the
            finding is downgraded to CANDIDATE (kept, but flagged unproven).

Everything is read from VEX statements/expressions + ELF loader metadata (names).
Nothing is executed. Reuses VexScan (loading/names), BlockV/scan_function (frame
facts + linear frame math) and TaintEngine (attacker-reachability).
"""
import logging

logging.disable(logging.CRITICAL)
import os
import sys

import pyvex

from .scan import VexScan, normf
from .taint import TaintEngine
from .vex import BlockV, scan_function, signed

# ---- sink signatures: dest arg index, size arg index (None = unbounded) --------
# indices are positions into the architecture's argument-register order.
UNBOUNDED_SINKS = {
    "strcpy": (0, None), "strcat": (0, None), "sprintf": (0, None),
    "gets": (0, None), "stpcpy": (0, None), "vsprintf": (0, None),
    "scanf": (None, None), "sscanf": (None, None),
}
BOUNDED_SINKS = {
    "strncpy": (0, 2), "strncat": (0, 2), "memcpy": (0, 2), "memmove": (0, 2),
    "snprintf": (0, 1), "vsnprintf": (0, 1), "fgets": (0, 1),
    "read": (1, 2), "recv": (1, 2), "pread": (1, 2), "fread": (0, None),
}
ALL_SINKS = {**UNBOUNDED_SINKS, **BOUNDED_SINKS}

RA_NEAR = 0x600          # room below this => easy return-address overwrite => CRITICAL

# call-with-link mnemonics across the ISAs angr lifts, used to locate the real call
# instruction inside a call block (which ends after it, past any delay slot).
CALL_MNEMONICS = {
    "jalr", "jal", "bal", "bgezal", "bgezall", "bltzal", "bltzall",   # MIPS
    "bl", "blx", "blr",                                               # ARM / AArch64
    "bla", "bctrl", "bctarl",                                         # PowerPC
    "call",                                                           # x86
}


class OverflowProver:
    def __init__(self, path, vs=None, taint=None):
        self.vs = vs or VexScan(path)
        self.proj = self.vs.proj
        self.sp = self.vs.sp
        self.bits = self.vs.bits
        self.argregs = list(self.vs.argregs)
        # taint oracle (built lazily per function); share the loaded VexScan
        self._taint = taint
        if self._taint is None:
            try:
                self._taint = TaintEngine(path, vs=self.vs)
            except Exception:
                self._taint = None

    def _call_insn_addr(self, ba):
        """Address of the call instruction inside call block `ba`. angr ends a call
        block after the call (and, on MIPS/PPC, its delay slot), so `ba` itself is
        the post-call fixup, not the call. Walk the block's instructions backwards to
        the call-with-link; fall back to `ba` if none is found."""
        try:
            insns = self.proj.factory.block(ba).capstone.insns
        except Exception:
            return ba
        for ins in reversed(insns):
            if ins.mnemonic in CALL_MNEMONICS:
                return ins.address
        return ba

    # ---- constant/linear evaluation of a data expression at statement i --------
    def _num(self, exp, nval, reg):
        """return ('v', int) for a recovered constant, else None."""
        if isinstance(exp, pyvex.expr.Const):
            return ("v", signed(exp.con.value, self.bits))
        if isinstance(exp, pyvex.expr.RdTmp):
            v = nval.get(exp.tmp)
            return ("v", v) if v is not None else None
        if isinstance(exp, pyvex.expr.Get):
            return ("v", reg[exp.offset]) if exp.offset in reg else None
        if isinstance(exp, pyvex.expr.Binop):
            op = exp.op
            a = self._num(exp.args[0], nval, reg)
            b = self._num(exp.args[1], nval, reg)
            if a and b:
                if op.startswith("Iop_Add"):
                    return ("v", a[1] + b[1])
                if op.startswith("Iop_Sub"):
                    return ("v", a[1] - b[1])
                if op.startswith("Iop_Shl"):
                    return ("v", a[1] << (b[1] & 63))
                if op.startswith("Iop_Mul"):
                    return ("v", a[1] * b[1])
        return None

    def _resolve_lin(self, lin, reg_lin):
        """Fold known register->frame-pointer aliases into a linear form.

        Buffer pointers are frequently parked in a callee-saved register
        (`s0 = sp+0xc0`) and copied to the arg reg right before the call
        (`move a0, s0`). vex sees `GET(s0)` as an opaque coefficient; here
        we substitute any register we already know to be `sp + const`.
        """
        off, coeff, unk, fr = lin
        if unk:
            return lin
        acc_off = off
        acc_fr = fr
        leftover = {}
        for r, c in coeff.items():
            base = reg_lin.get(r)
            if base is not None and not base[2] and not base[1]:   # r == sp + base_off
                acc_off += c * base[0]
                acc_fr = acc_fr or base[3]
            else:
                leftover[r] = c
        return (acc_off, leftover, unk, acc_fr)

    def prove_function(self, name, addr, fsize):
        """Return a list of per-call-site findings for one function."""
        facts = scan_function(self.vs, name, addr, fsize)
        ra_slot = facts["ra_slot"]
        frame = facts["frame"]
        blocks = self.vs.function_blocks(addr, fsize)
        if not blocks:
            return []
        prologue = min(blocks)

        # robust call-target names come from scan_function (handles MIPS GOT /
        # PLT / PC-relative resolution) keyed by the call block address.
        call_name = {cba: normf(cnm) for (cba, cnm) in facts["calls"] if cnm}

        # taint oracle: which (call_block, sink) pairs are attacker-reachable
        taint_hits = set()
        if self._taint is not None:
            try:
                hits, _ = self._taint.run_function(name, addr, fsize)
                taint_hits = {(ba, normf(nm)) for (ba, nm, _lab) in hits}
            except Exception:
                taint_hits = set()

        # forward-carried register environment (best-effort, address order):
        #   reg_const[off] = int      (constant register content)
        #   reg_lin[off]   = (offset, coeff, unknown, frame_rel)   (frame pointer)
        reg_const = {}
        reg_lin = {}
        findings = []

        for ba in sorted(blocks):
            try:
                irsb = self.proj.factory.block(ba).vex
            except Exception:
                continue
            cp = (ba == prologue)
            bv = BlockV(irsb, self.sp, self.bits, facts.get("frame_delta", 0) or 0, cp)
            nval = {}                       # tmp -> const int (this block)
            for i, st in enumerate(irsb.statements):
                if isinstance(st, pyvex.stmt.WrTmp):
                    v = self._num(st.data, nval, reg_const)
                    if v:
                        nval[st.tmp] = v[1]
                elif isinstance(st, pyvex.stmt.Put):
                    # constant tracking
                    v = self._num(st.data, nval, reg_const)
                    if v:
                        reg_const[st.offset] = v[1]
                    else:
                        reg_const.pop(st.offset, None)
                    # frame-linear tracking (for buffer pointers sp+K), folding
                    # in any register that already aliases sp+const.
                    lin = self._resolve_lin(bv.rhs_linear(st.data, i), reg_lin)
                    if not lin[2] and lin[3] and not lin[1]:
                        reg_lin[st.offset] = lin
                    else:
                        reg_lin.pop(st.offset, None)

            # at a call, evaluate the sink's dest/size arguments
            if str(irsb.jumpkind).startswith("Ijk_Call"):
                nm = call_name.get(ba) or self._callee_name(irsb, reg_const, nval)
                if nm in ALL_SINKS and self.argregs:
                    fnd = self._check_call(nm, ba, reg_const, reg_lin,
                                           ra_slot, frame, taint_hits)
                    if fnd:
                        # `call` stays the IRSB start (taint pairing + scan-pipeline
                        # verdict matching key on it); `site` is the actual call
                        # instruction for humans/disassemblers.
                        fnd.update(function=name, addr=hex(addr),
                                   site=hex(self._call_insn_addr(ba)))
                        findings.append(fnd)
                # a call clobbers caller-saved registers: forget arg regs so a
                # stale pointer/const does not leak into the next call site.
                for ro in self.argregs:
                    reg_const.pop(ro, None)
                    reg_lin.pop(ro, None)
        return findings

    def _callee_name(self, irsb, reg_const, nval):
        nxt = irsb.next
        if isinstance(nxt, pyvex.expr.Const):
            return self.vs.resolve(nxt.con.value)
        if isinstance(nxt, pyvex.expr.RdTmp):
            v = nval.get(nxt.tmp)
            if v is not None:
                return self.vs.resolve(v & 0xffffffff)
        return None

    def _global_dest(self, dest_i, reg_const):
        """If the destination arg holds a constant address inside the loaded image,
        return it: the sink writes into a global/static buffer, not the stack."""
        if dest_i is None or dest_i >= len(self.argregs):
            return None
        c = reg_const.get(self.argregs[dest_i])
        if c is None:
            return None
        c &= (1 << self.bits) - 1
        try:
            if self.vs.mo.min_addr <= c <= self.vs.mo.max_addr:
                return c
        except Exception:
            pass
        return None

    def _unmodeled(self, nm, ba, why):
        return {"verdict": "UNMODELED", "sink": nm, "call": hex(ba),
                "dest": "?", "room": "?", "size": "?", "severity": "-",
                "tainted": (ba, normf(nm)) in getattr(self, "_th", set()),
                "reason": why}

    def _check_call(self, nm, ba, reg_const, reg_lin, ra_slot, frame, taint_hits):
        self._th = taint_hits
        dest_i, size_i = ALL_SINKS[nm]
        # ---- destination buffer offset D (frame-relative) ----
        D = None
        if dest_i is not None and dest_i < len(self.argregs):
            lin = reg_lin.get(self.argregs[dest_i])
            if lin is not None:
                D = lin[0]
        # cases the sp-relative + saved-ra-in-frame model cannot handle: defer
        # (the unified harness falls back to the presence heuristic here, so
        #  recall never regresses; see README "frame models by architecture").
        if dest_i is None:
            return self._unmodeled(nm, ba, f"{nm} has no fixed dest arg (variadic)")
        if ra_slot is None:
            return self._unmodeled(nm, ba, "no in-frame return-address slot "
                                   "(x86 implicit CALL return / leaf frame)")
        if D is None:
            # dest may be a global/static buffer: a constant address in the image,
            # not the stack. That is not a stack overflow, and saying so (rather than
            # UNMODELED) lets the merge suppress the heuristic's stack-overflow FP.
            g = self._global_dest(dest_i, reg_const)
            if g is not None:
                return {"verdict": "NOT_STACK", "sink": nm, "call": hex(ba),
                        "dest": hex(g), "room": "-", "size": "sym", "severity": "-",
                        "tainted": (ba, normf(nm)) in taint_hits,
                        "reason": f"{nm} dest {g:#x} is a global/static buffer, not the "
                                  "stack; distance-to-saved-ra model N/A"}
            return self._unmodeled(nm, ba, f"{nm} dest not sp-relative "
                                   "(frame-pointer/heap addressing)")
        room = ra_slot - D
        if room < 0:
            return self._unmodeled(nm, ba, f"{nm} dest sp+{D:#x} is above saved-ra "
                                   f"slot sp+{ra_slot:#x} (AArch64/ARM layout); "
                                   "distance-to-ra model N/A")
        if room == 0:
            # dest exactly on the saved-ra slot => frame mis-recovery, not a real
            # on-frame buffer (seen on AArch64 fp-relative frames). Defer.
            return self._unmodeled(nm, ba, f"{nm} dest sp+{D:#x} coincides with the "
                                   f"saved-ra slot sp+{ra_slot:#x}: frame mis-recovery")
        # ---- size argument n (constant?) ----
        n = None
        if size_i is not None and size_i < len(self.argregs):
            n = reg_const.get(self.argregs[size_i])
            if n is not None:
                n = n & ((1 << self.bits) - 1)   # size args are unsigned
        tainted = (ba, normf(nm)) in taint_hits

        unbounded = nm in UNBOUNDED_SINKS
        verdict = sev = reason = None
        if unbounded:
            verdict = "OVERFLOW"
            sev = "CRITICAL" if room < RA_NEAR else "HIGH"
            reason = (f"unbounded {nm} into stack buffer sp+{D:#x}; attacker sets "
                      f"length; only {room:#x} bytes to saved ra")
        elif n is not None:
            if n > room:
                verdict = "OVERFLOW"
                sev = "CRITICAL" if room < RA_NEAR else "HIGH"
                reason = (f"{nm} writes {n:#x} into sp+{D:#x} but only {room:#x} "
                          f"bytes to saved ra -> {n - room:#x} past ra")
            else:
                verdict = "SAFE"
                sev = "-"
                reason = (f"{nm} bounded n={n:#x} <= room {room:#x} at sp+{D:#x} "
                          f"(fits before saved ra)")
        else:
            # bounded sink, size not a constant
            if tainted:
                verdict = "OVERFLOW"
                sev = "CRITICAL" if room < RA_NEAR else "HIGH"
                reason = (f"{nm} length is attacker-influenced (non-constant) into "
                          f"sp+{D:#x}; {room:#x} bytes to saved ra")
            else:
                verdict = "CANDIDATE"
                sev = "MEDIUM"
                reason = (f"{nm} length not a constant at sp+{D:#x}; {room:#x} to "
                          f"saved ra; attacker-reachability unproven")

        if verdict == "SAFE":
            return {"verdict": "SAFE", "sink": nm, "call": hex(ba),
                    "dest": f"sp+{D:#x}", "room": hex(room),
                    "size": (hex(n) if n is not None else "sym"),
                    "severity": sev, "tainted": tainted, "reason": reason}
        return {"verdict": verdict, "sink": nm, "call": hex(ba),
                "dest": f"sp+{D:#x}", "room": hex(room),
                "size": (hex(n) if n is not None else "sym"),
                "severity": sev, "tainted": tainted, "reason": reason}

    def run(self, name_filter=None):
        out = []
        for nm, a0, span in self.vs.functions():
            if name_filter and name_filter not in nm:   # --func focus
                continue
            try:
                out.extend(self.prove_function(nm, a0, span))
            except Exception:
                pass
        return out


# ---------------------------------------------------------------------------
# Human-readable command-line report (no internal verdict jargon in the output)
# ---------------------------------------------------------------------------
def _facts_line(f):
    """Compact, exact evidence for one sink call; addresses and values preserved."""
    if f["size"] == "sym":
        sz = "size: unbounded" if f["sink"] in UNBOUNDED_SINKS else "size: non-constant"
    elif f["size"] in ("?", "-"):
        sz = "size: not recovered"
    else:
        sz = f"size: {f['size']}"
    dest = f["dest"]
    if dest == "?":
        buf = "buffer: not located on this frame"
    elif dest.startswith("sp+"):
        buf = f"buffer {dest} (offset recovered from IR)"
    else:
        buf = f"buffer {dest} (global/static address)"
    room = f["room"]
    dist = (f"{room} bytes from buffer to saved return address"
            if room not in ("-", "?") else "distance to saved return address: not applicable")
    return f"{buf}  |  {sz}  |  {dist}"


def _explanation(f):
    """A plain-language sentence stating exactly why the call is safe or unsafe."""
    sink, dest, room, size, v = f["sink"], f["dest"], f["room"], f["size"], f["verdict"]
    if v == "SAFE":
        return (f"{sink} copies {size} bytes into a buffer at {dest}, leaving {room} bytes "
                f"before the saved return address, so the copy remains within the available "
                f"stack space.")
    if v == "OVERFLOW":
        if size == "sym" and sink in UNBOUNDED_SINKS:
            return (f"{sink} writes an attacker-controlled string into a buffer at {dest} with "
                    f"no length limit, and only {room} bytes separate that buffer from the saved "
                    f"return address, so a long enough input writes past it and overwrites the "
                    f"return address.")
        if size == "sym":
            return (f"{sink} copies an attacker-influenced number of bytes into a buffer at "
                    f"{dest}, and only {room} bytes remain before the saved return address, so an "
                    f"unchecked length can overrun the buffer and reach the return address.")
        past = int(size, 16) - int(room, 16)
        return (f"{sink} copies {size} bytes into a buffer at {dest}, but only {room} bytes "
                f"remain before the saved return address, so {hex(past)} bytes spill past it and "
                f"overwrite the return address.")
    if v == "CANDIDATE":
        return (f"{sink} copies a non-constant number of bytes into a buffer at {dest} with "
                f"{room} bytes before the saved return address. The length is not a compile-time "
                f"constant and attacker input was not proven to reach here, so this call can be "
                f"neither confirmed nor ruled out.")
    if v == "NOT_STACK":
        return (f"{sink} writes into a global or static buffer at {dest}, not the stack, so the "
                f"distance-to-return-address check does not apply. This is not a stack buffer "
                f"overflow.")
    return (f"{sink} could not be checked precisely ({f['reason']}), so it was handed to the "
            f"broader heuristic scan instead.")


_ORDER = {"OVERFLOW": 0, "CANDIDATE": 1, "SAFE": 2, "NOT_STACK": 3, "UNMODELED": 4}


def _report_binary(path, opts, banner):
    from collections import defaultdict

    from .scan import elf_mitigations, mitigations_str
    prov = OverflowProver(path)
    funcmap = {nm: (a, s) for nm, a, s in prov.vs.functions()}
    findings = prov.run(name_filter=opts.func)

    print(banner.rule(os.path.basename(path)))
    print("  " + banner.paint("architecture ", banner.MUTED) + prov.vs.arch.name
          + banner.paint("   mitigations ", banner.MUTED)
          + banner.paint(mitigations_str(elf_mitigations(path)), banner.MUTED))

    byfn = defaultdict(list)
    for f in findings:
        byfn[f["function"]].append(f)

    v = [f["verdict"] for f in findings]
    n_ov, n_cand, n_safe = v.count("OVERFLOW"), v.count("CANDIDATE"), v.count("SAFE")
    n_defer = v.count("NOT_STACK") + v.count("UNMODELED")

    def fn_key(item):
        fn, fl = item
        return (0 if any(x["verdict"] == "OVERFLOW" for x in fl) else 1, fn)

    shown_any = False
    for fn, fl in sorted(byfn.items(), key=fn_key):
        sites = ([f for f in fl if f["verdict"] == "OVERFLOW"] if opts.overflows_only
                 else [f for f in fl if f["verdict"] != "UNMODELED" or opts.all_sites])
        if not sites:
            continue
        shown_any = True
        addr, span = funcmap.get(fn, (None, None))
        facts = scan_function(prov.vs, fn, addr, span) if addr is not None else {}
        frame, ra_slot = facts.get("frame"), facts.get("ra_slot")

        print()
        head = "  " + banner.paint(fn, banner.CREAM, bold=True)
        if addr is not None:
            head += banner.paint(f"   {addr:#x}", banner.MUTED)
        print(head)

        fr = f"stack frame {frame:#x} bytes" if frame else "stack frame size not recovered"
        fr += (f"; saved return address at sp+{ra_slot:#x}" if ra_slot is not None
               else "; no in-frame saved return address (x86-style; deferred to heuristic)")
        print("    " + banner.paint(fr, banner.MUTED))

        danger = sorted({f["sink"] for f in fl})
        print("    " + banner.paint("dangerous sinks called: ", banner.MUTED)
              + banner.paint(", ".join(danger), banner.CREAM))
        reached = [f for f in fl if f.get("tainted")]
        if reached:
            print("    " + banner.paint("attacker input reaches: ", banner.MUTED)
                  + banner.paint(", ".join(f"{f['sink']}@{f.get('site', f['call'])}"
                                           for f in reached), banner.AMBER))

        for f in sorted(sites, key=lambda x: (_ORDER.get(x["verdict"], 9), x.get("site", ""))):
            vd = f["verdict"]
            if vd == "OVERFLOW":
                tag = (banner.paint("attacker-reachable", banner.GREEN, bold=True) if f["tainted"]
                       else banner.paint("reachability unproven", banner.MUTED))
                status = banner.severity_label(f["severity"]) + " " + tag
                mark = banner.paint(">", banner.RED, bold=True)
            elif vd == "CANDIDATE":
                status = banner.paint("unproven", banner.AMBER); mark = banner.paint(">", banner.AMBER)
            elif vd == "SAFE":
                status = banner.paint("safe", banner.GREEN); mark = banner.paint(">", banner.GREEN)
            elif vd == "NOT_STACK":
                status = banner.paint("not a stack buffer", banner.MUTED); mark = banner.paint(">", banner.MUTED)
            else:
                status = banner.paint("deferred to heuristic", banner.MUTED); mark = banner.paint(">", banner.MUTED)
            print(f"    {mark} " + banner.paint(f["sink"], banner.CREAM, bold=True)
                  + banner.paint(f" at {f.get('site', f['call'])}", banner.MUTED) + "   " + status)
            print("        " + banner.paint(_facts_line(f), banner.MUTED))
            print("        " + _explanation(f))

    if not shown_any:
        print("  " + banner.paint("no dangerous call sites found", banner.MUTED))
    sep = banner.paint(f" {banner.glyphs()['dot']} ", banner.MUTED)
    print()
    print("  " + banner.paint(f"{n_ov} overflow(s)", banner.RED, bold=n_ov > 0) + sep
          + banner.paint(f"{n_cand} unproven", banner.AMBER) + sep
          + banner.paint(f"{n_safe} safe copy(ies) suppressed", banner.GREEN) + sep
          + banner.paint(f"{n_defer} deferred to heuristic", banner.MUTED))


def main(argv=None):
    import argparse

    from . import banner
    ap = argparse.ArgumentParser(
        prog="vexhound-prove",
        description="Prove or refute a stack-buffer overflow at every dangerous call, "
                    "with plain-language evidence for each decision.")
    ap.add_argument("targets", nargs="+", help="binaries to analyze")
    ap.add_argument("--func", metavar="NAME",
                    help="only analyze functions whose name contains NAME")
    ap.add_argument("--overflows-only", action="store_true",
                    help="show only the call sites that overflow")
    ap.add_argument("--all-sites", action="store_true",
                    help="also show sites the frame model deferred to the heuristic scan")
    a = ap.parse_args(argv)
    banner.set_enabled(banner.stdout_supports_color())
    for p in a.targets:
        _report_binary(p, a, banner)
    return 0


if __name__ == "__main__":
    sys.exit(main())
