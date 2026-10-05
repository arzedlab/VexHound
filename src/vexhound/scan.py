"""
scan.py: vulnerability pattern detector that reads ONLY angr VEX IR.

No capstone, no raw-byte scanning, no mnemonic/op_str matching.
All arithmetic is over `pyvex` statements/expressions lifted by angr, plus
angr/CLE metadata for function inventory, register offsets and import names.

Facts recovered per function (vex.BlockV + scan_function):
   frame   : size of stack frame          (prologue PUT(sp)=sp+delta)
   gp      : MIPS $gp constant            (PUT(gp)=const)
   ra_slot : frame-relative offset where the saved return address is stored
             (Store whose data is GET(ra))
   calls   : (irsb_addr, resolved name)   (Ijk_Call; const/indirect via GOT)
   arg0    : frame-relative offsets pushed to the first argument register

Verdicts (same rules as batch_scan.py, but computed purely on the IR):
   F1 stack overflow : unbounded string sink + parsed-input getter, OR a
                       measured to_ra = ra_slot - K < 0x600
   F3 command injection: system/popen/exec* + strong getter
   F6 format string   : printf-family + strong getter (candidate)
Nothing is executed.
"""
import logging

logging.disable(logging.CRITICAL)
import bisect
import struct
import sys

import angr
import pyvex

from .vex import normf, scan_function

UNBOUNDED = {"sprintf", "strcpy", "strcat", "gets"}
F1_MEAS = {"snprintf", "strncpy", "memcpy", "memmove", "read", "recv", "fgets", "fread", "getline"}
F3_SINKS = {"system", "popen", "execlp", "execl", "execvp", "execve"}
F6_SINKS = {"printf", "fprintf", "vfprintf", "vsprintf", "sprintf"}
STRONG = {"getenv", "sobj_get_string", "sess_get_uid", "cgibin_parse_request",
          "sobj_unescape_uri", "sobj_strdup", "getline", "ixmlParseBuffer",
          "sscanf", "sobj_xstream_read", "websGetVar",
          # web-server request getters seen in real firmware (TP-Link/embedded httpd)
          "httpGetEnv", "http_get_env", "httpGetValue", "web_get"}


def elf_mitigations(path):
    """Exploit mitigations present in the ELF, which change how much a proven
    overflow is worth: a canary usually turns a saved-ra overwrite into a caught
    abort (DoS) rather than clean control-flow hijack. Read straight from the ELF,
    the same records `checksec` uses. Returns a dict; unknown fields stay None."""
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    out = {"canary": None, "nx": None, "pie": None, "relro": None}
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            out["pie"] = (elf.header["e_type"] == "ET_DYN")
            relro = False
            for seg in elf.iter_segments():
                t = seg["p_type"]
                if t == "PT_GNU_STACK":
                    out["nx"] = not bool(seg["p_flags"] & 0x1)   # PF_X
                elif t == "PT_GNU_RELRO":
                    relro = True
            names = set()
            for secname in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(secname)
                if sec:
                    names.update(s.name for s in sec.iter_symbols() if s.name)
            out["canary"] = ("__stack_chk_fail" in names or
                             "__stack_chk_guard" in names)
            bind_now = False
            for sec in elf.iter_sections():
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        d_tag, d_val = tag.entry.d_tag, tag.entry.d_val
                        if d_tag == "DT_BIND_NOW" or d_tag == "DT_FLAGS" and d_val & 0x8 or d_tag == "DT_FLAGS_1" and d_val & 0x1:
                            bind_now = True
            out["relro"] = "full" if (relro and bind_now) else "partial" if relro else "none"
    except Exception:
        pass
    return out


def mitigations_str(m):
    """One-line render of an elf_mitigations() dict for console/CSV."""
    def yn(v):
        return "yes" if v is True else "no" if v is False else "?"
    m = m or {}
    return (f"canary={yn(m.get('canary'))} nx={yn(m.get('nx'))} "
            f"pie={yn(m.get('pie'))} relro={m.get('relro') or '?'}")


class VexScan:
    def __init__(self, path):
        self.path = path
        self.proj = angr.Project(path, auto_load_libs=False)
        self.arch = self.proj.arch
        self.mo = self.proj.loader.main_object
        self.bits = self.arch.bits
        self.nm2off = {}
        for nm, (off, sz) in self.arch.registers.items():
            self.nm2off.setdefault(nm, (off, sz))
        self.sp = self.nm2off.get("sp", (None,))[0]
        self.gp_off = self.nm2off.get("gp", (None,))[0]
        self.t9 = self.nm2off.get("t9", (None,))[0]   # MIPS PIC: gp = f(t9=entry)
        self.ra = None
        for nm in ("ra", "lr", "x30", "link", "r30"):
            if nm in self.nm2off:
                self.ra = self.nm2off[nm][0]
                break
        self.argregs = []
        try:
            ccargs = list(self.proj.factory.cc().ARG_REGS or [])
        except Exception:
            ccargs = []
        for nm0 in ccargs:
            if isinstance(nm0, int):
                self.argregs.append(nm0)
            elif nm0 in self.nm2off:
                self.argregs.append(self.nm2off[nm0][0])
        # import resolution map
        self.stub = {}
        try:
            for nm0, ra0 in (getattr(self.mo, "plt", {}) or {}).items():
                self.stub[ra0] = normf(nm0)
        except Exception:
            pass
        for s in self.mo.symbols:
            if s.name and not s.is_import:
                try:
                    ra0 = s.rebased_addr
                    if ra0 and ra0 != 0:
                        self.stub.setdefault(ra0, normf(s.name))
                except Exception:
                    pass
        # MIPS O32 GOT
        self.got = {}
        if self.arch.name.startswith("MIPS"):
            self.got = self._load_mips_got()
        self.mitigations = elf_mitigations(path)
        self._cfg = None
        self._blkstarts = None
        self._funcs = None

    def _load_mips_got(self):
        """Map each global MIPS GOT slot to its imported symbol name, for resolving
        PIC calls (lw $t9, off($gp); jalr $t9). Works for executables AND shared
        objects: file offsets are derived from the ELF's own PT_LOAD vaddrs (not the
        rebased min_addr), and slot addresses are rebased into angr's address space
        by the load delta. The old code assumed an executable (vaddr == file offset
        + min_addr, and a `_gp` symbol), so every .so read a negative offset and
        bailed with an empty map."""
        try:
            from elftools.elf.elffile import ELFFile
            raw = open(self.path, "rb").read()
            elf = ELFFile(open(self.path, "rb"))
            # Read the dynamic info from the PT_DYNAMIC *segment*, not the
            # .dynamic/.dynsym *sections*: shipped firmware routinely strips
            # section headers, and the old section-based path then returned an
            # empty GOT map, blinding every stripped MIPS binary.
            dynseg = next((g for g in elf.iter_segments()
                           if g.header.p_type == "PT_DYNAMIC"), None)
            if dynseg is None:
                return {}
            tags = {t.entry.d_tag: t.entry.d_val for t in dynseg.iter_tags()}
            for k in ("DT_SYMTAB", "DT_STRTAB", "DT_MIPS_LOCAL_GOTNO", "DT_MIPS_GOTSYM"):
                if k not in tags:
                    return {}
            # GOT base vaddr: DT_PLTGOT points at the GOT on MIPS; the `_gp` symbol
            # (gotbase + 0x7ff0) is only a fallback since shared objects often omit it.
            gotbase = tags.get("DT_PLTGOT")
            if gotbase is None:
                gp = next((s["st_value"] for s in dynseg.iter_symbols()
                           if s.name == "_gp"), None)
                if not gp:
                    return {}
                gotbase = gp - 0x7FF0
            # linked vaddr -> file offset, from PT_LOAD (independent of rebasing)
            loads = [(g["p_vaddr"], g["p_offset"], g["p_filesz"])
                     for g in elf.iter_segments() if g["p_type"] == "PT_LOAD"]

            def foff(vaddr):
                for v, o, sz in loads:
                    if v <= vaddr < v + sz:
                        return o + (vaddr - v)
                return None

            delta = self.mo.mapped_base - self.mo.linked_base   # rebase into angr space
            fmt = "<" if self.arch.memory_endness == "Iend_LE" else ">"
            st, sts = tags["DT_SYMTAB"], tags["DT_STRTAB"]
            gotno, gotsym = tags["DT_MIPS_LOCAL_GOTNO"], tags["DT_MIPS_GOTSYM"]
            symsize = 16 if self.bits == 32 else 24     # Elf32_Sym / Elf64_Sym
            # total dynamic symbol count: DT_MIPS_SYMTABNO (present on MIPS),
            # else walk the segment symbol table (works without section headers).
            symcount = tags.get("DT_MIPS_SYMTABNO")
            if symcount is None:
                try:
                    symcount = dynseg.num_symbols()
                except Exception:
                    return {}
            out = {}
            for ent in range(gotno, gotno + max(0, symcount - gotsym)):
                idx = gotsym + (ent - gotno)
                so = foff(st + idx * symsize)     # st_name is word 0 of the symbol
                if so is None or so + 4 > len(raw):
                    break
                st_name = struct.unpack(fmt + "I", raw[so:so + 4])[0]
                no = foff(sts + st_name)
                if no is None:
                    continue
                e = raw.find(b"\x00", no)
                if e > no:
                    out[gotbase + ent * 4 + delta] = raw[no:e].decode("latin1", "replace")
            return out
        except Exception:
            return {}

    def resolve(self, addr):
        for cand in (addr, addr & 0xffffffff, addr & 0xfffffffe, addr - 1):
            n = self.stub.get(cand)
            if n:
                return normf(n)
        return None

    def cfg(self):
        if self._cfg is None:
            self._cfg = self.proj.analyses.CFGFast(normalize=True)
        return self._cfg

    def _block_starts(self):
        """Sorted union of every basic-block start the CFG knows. Block boundaries
        are reliable even where angr mis-assigns a block to the wrong function, so
        we slice this list by [entry, next_entry) to recover a function's own body."""
        if self._blkstarts is None:
            s = set()
            try:
                for fn in self.cfg().functions.values():
                    s.update(fn.block_addrs)
            except Exception:
                pass
            self._blkstarts = sorted(s)
        return self._blkstarts

    def functions(self):
        """Canonical analysis units as (name, entry, span), covering symbolized AND
        anonymous functions. Entry points come from .dynsym, the CFG's own function
        starts, and predecessors that angr wrongly folded into a later symbol (its
        block set dips below the entry). `span` is the distance to the next entry, so
        function_blocks() can carve out each body without bleeding into a neighbour.
        This replaces the old symbol-table-only inventory, which never saw the many
        stripped/anonymous helpers where real sinks live."""
        if self._funcs is not None:
            return self._funcs
        minaddr = self.mo.min_addr
        names = {}                              # entry addr -> analysis name
        boundaries = set()                      # every entry, incl. boundary-only
        for s in self.mo.symbols:
            if not (s.name and not s.is_import and
                    "STT_FUNC" in str(getattr(s, "subtype", ""))):
                continue
            try:
                a = s.rebased_addr
            except Exception:
                continue
            if not a or a < minaddr:
                continue
            boundaries.add(a)                   # bounds neighbours even if we skip it
            nm = normf(s.name)
            if nm and not nm.startswith("_"):
                names[a] = nm
        try:
            for fn in self.cfg().functions.values():
                a = fn.addr
                if not a or a < minaddr:
                    continue
                boundaries.add(a)
                names.setdefault(a, normf(fn.name) if fn.name else f"sub_{a:x}")
                ba = fn.block_addrs
                if ba:
                    lo = min(ba)
                    if lo < a and lo >= minaddr:   # angr folded a preceding function in
                        boundaries.add(lo)
                        names.setdefault(lo, f"sub_{lo:x}")
        except Exception:
            pass
        ordered = sorted(boundaries)
        out = []
        for i, a in enumerate(ordered):
            nm = names.get(a)
            if not nm or nm.startswith("_"):
                continue                        # boundary-only (libc internal): not analysed
            hi = ordered[i + 1] if i + 1 < len(ordered) else a + 0x8000
            span = hi - a
            if span <= 0:
                continue
            out.append((nm, a, min(span, 0x8000)))
        self._funcs = out
        return out

    def function_blocks(self, addr, fsize):
        """Basic-block starts of the function at `addr`, bounded above by
        `addr+fsize` (the distance to the next entry from functions()). Sliced from
        the CFG's block boundaries with a real lower bound, so a tiny thunk symbol or
        a symbol preceded by anonymous code can no longer swallow a neighbour's
        blocks. Linear fallback when the CFG has nothing here."""
        hi = addr + (fsize if fsize and 0 < fsize < 0x40000 else 0x8000)
        starts = self._block_starts()
        out = starts[bisect.bisect_left(starts, addr):bisect.bisect_left(starts, hi)]
        if out:
            return list(out)
        # linear fallback: fallthrough/branch chain from addr, bounded by hi
        got = set()
        cur = addr & ~1
        while cur is not None and cur not in got and cur < hi:
            got.add(cur)
            try:
                irsb = self.proj.factory.block(cur).vex
            except Exception:
                break
            nxt = irsb.next
            if isinstance(nxt, pyvex.expr.Const):
                cur = nxt.con.value
                if cur <= addr or cur >= hi:
                    break
            else:
                break
        return sorted(got)

    def run(self):
        findings = []
        inv = self.functions()
        if not inv:
            inv = [("main", self.proj.entry, 0x400)]
        for (nm, a0, sz) in inv:
            try:
                fs = self._verdict(nm, a0, sz)
                findings.extend(fs)
            except Exception as e:
                findings.append({"function": nm, "family": "error", "severity": "-",
                                 "note": f"{type(e).__name__}: {str(e)[:90]}",
                                 "addr": hex(a0), "detail": ""})
        return findings

    def _verdict(self, nm, a0, sz):
        f = scan_function(self, nm, a0, sz)
        names = f["names"]
        nset = {normf(x) for x in names}
        has_getter = bool(nset & STRONG)
        unb = [n for n in nset if n in UNBOUNDED]
        f1m = [n for n in nset if n in F1_MEAS]
        f3 = [n for n in nset if n in F3_SINKS]
        f6 = [n for n in nset if n in F6_SINKS]
        extra = []
        if f["frame"]:
            extra.append(f"frame={f['frame']:#x}")
        if f["ra_slot"] is not None:
            extra.append(f"ra_slot=sp+{f['ra_slot']:#x}")
        to_ra = None
        # choose the deepest buffer? just record the largest K with a valid to_ra
        if f["ra_slot"] is not None and f["arg0_frame"]:
            best = None
            for (ba, K) in f["arg0_frame"]:
                if K >= 0:
                    t = f["ra_slot"] - K
                    if t >= 0 and (best is None or K > best[1]):
                        best = (t, K)
            if best:
                to_ra = best[0]
                extra.append(f"sink->sp+{best[1]:#x}")
        if to_ra is not None:
            extra.append(f"to_ra={to_ra:#x}")

        sinkpool = set(unb) | set(f1m)
        flags = []
        if (unb and has_getter) or (to_ra is not None and f["frame"] and sinkpool):
            sev = "CRITICAL" if (to_ra is not None and to_ra < 0x600) else "HIGH"
            sinks = ",".join(sorted(sinkpool)[:4]) or "unbounded"
            note = f"F1 sink ({sinks}) in parsed-input path"
            if to_ra is not None:
                note += f"; stack dest within {to_ra:#x} of saved $ra"
            flags.append(("stack-buffer-overflow", sev, note, "; ".join(extra)))
        if f3 and has_getter:
            flags.append(("command-injection", "HIGH",
                          "F3 sink (" + ",".join(sorted(f3)[:4]) + ") with parsed-input getter",
                          "; ".join(extra)))
        if f6 and has_getter and not flags:
            flags.append(("format-string", "MEDIUM",
                          "format-string candidate in parsed-input path", "; ".join(extra)))
        out = []
        for (fam, sev, note, det) in flags[:3]:
            out.append({"function": nm, "family": fam, "severity": sev,
                        "note": note, "detail": det, "addr": hex(a0),
                        "calls": ",".join(names[:60])})
        return out


def main():
    for p in sys.argv[1:]:
        print("=" * 78)
        print("BINARY:", p)
        vs = VexScan(p)
        fs = vs.run()
        if not fs:
            print("  (no findings)")
        for f in fs:
            print(f"  [{f['family']:22}] {f['severity']:8} {f['function']}  {f.get('addr', '')}")
            print(f"        note:   {f['note']}")
            print(f"        detail: {f['detail']}")
            if f.get("calls"):
                print(f"        calls:  {f['calls'][:120]}")


if __name__ == "__main__":
    main()
