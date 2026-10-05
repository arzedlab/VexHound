"""vex.py: VEX-IR value numbering used by scan.py.

Representation of an expression's meaning at a given program point:

    lin = (offset:int, coeff:{reg_off:int}, unknown:bool, frame_rel:bool)

* offset   = constant term measured from the FUNCTION FRAME sp (the sp value
             in effect after the prologue `PUT(sp)`).
* coeff    = contributions of registers other than sp.
* frame_rel= the expression references the stack (sp).
* unknown  = a construct we refuse to approximate (Multiply/Load/Or/...).

sp-generation:
    GET(sp) BEFORE the frame PUT (i.e. in the prologue block, before PUT(sp))
        reads the incoming sp -> offset = -frame_delta  (old sp = frame - delta)
    GET(sp) AFTER the frame PUT (prologue tail or any other block)
        reads the frame sp    -> offset = 0
This puts the ra-save `STle(sp+0x4e4)` and buffer `a0=sp+0xc0` on the SAME
base, so `to_ra = ra_slot - K` is sound.
"""
import pyvex

ADD = {"Iop_Add32", "Iop_Add64", "Iop_Add8", "Iop_Add16", "Iop_Add16x8", "Iop_Add8x16"}
SUB = {"Iop_Sub32", "Iop_Sub64", "Iop_Sub8", "Iop_Sub16"}


def normf(n):
    n = (n or "").split("@", 1)[0]
    return n.rsplit(".", 1)[-1] if "." in n else n


def signed(v, bits):
    if bits == 64:
        return v - (1 << 64) if v >= (1 << 63) else v
    return v - (1 << 32) if v >= (1 << 31) else v


def merge(a, b):
    return (a[0] + b[0],
            {k: a[1].get(k, 0) + b[1].get(k, 0) for k in set(a[1]) | set(b[1])},
            a[2] or b[2], a[3] or b[3])


def neg(a):
    return (-a[0], {k: -v for k, v in a[1].items()}, a[2], a[3])


def lin_const(v, bits):
    return (signed(v, bits), {}, False, False)


class BlockV:
    """Linear value-numbering for one IRSB with sp-generation handled."""

    def __init__(self, irsb, sp_off, bits, frame_delta, contains_put):
        self.irsb = irsb
        self.sp_off = sp_off
        self.bits = bits
        self.frame_delta = frame_delta        # signed prologue delta (<0)
        self.put_idx = None                   # index of PUT(sp) in THIS block
        self.contains_put = contains_put      # block holds the frame PUT(sp)
        if contains_put:
            self._find_put()
        self.memo = {}
        self._number()

    def _find_put(self):
        """VEX splits the prologue into  WrTmp t=Add(sp,const); Put(sp)=RdTmp(t)
        so follow the tmp.  Returns the delta when this block allocates the frame."""
        # collect WrTmp whose value = GET(sp) or = Add/Sub(GET-sp-chain, const)
        sp_tmps = set()
        pre = {}
        for j, st in enumerate(self.irsb.statements):
            if not isinstance(st, pyvex.stmt.WrTmp):
                continue
            d = st.data
            if isinstance(d, pyvex.expr.Get) and d.offset == self.sp_off:
                sp_tmps.add(st.tmp)
                pre[st.tmp] = 0
            elif (isinstance(d, pyvex.expr.Binop) and d.op in ADD | SUB):
                a0 = d.args[0]
                a1 = d.args[1]
                base_tmp = None
                c = 0
                # chain: Add(sp_tmp, const)  or  Add(GET sp, const)
                if isinstance(a0, pyvex.expr.RdTmp) and a0.tmp in sp_tmps and isinstance(a1, pyvex.expr.Const):
                    base_tmp = a0.tmp
                    c = signed(a1.con.value, self.bits)
                elif isinstance(a0, pyvex.expr.Get) and a0.offset == self.sp_off and isinstance(a1, pyvex.expr.Const):
                    sp_tmps.add(st.tmp)
                    c = signed(a1.con.value, self.bits)
                if base_tmp is not None:
                    if d.op.startswith("Iop_Sub"):
                        c = -c
                    pre[st.tmp] = c + pre.get(base_tmp, 0)
                    sp_tmps.add(st.tmp)
        for i, st in enumerate(self.irsb.statements):
            if isinstance(st, pyvex.stmt.Put) and st.offset == self.sp_off:
                d = st.data
                if isinstance(d, pyvex.expr.RdTmp) and d.tmp in pre:
                    self.put_idx = i
                    self.frame_delta = pre[d.tmp]
                    return
                if (isinstance(d, pyvex.expr.Binop) and d.op in ADD | SUB and
                        isinstance(d.args[0], pyvex.expr.Get) and d.args[0].offset == self.sp_off and
                        isinstance(d.args[1], pyvex.expr.Const)):
                    self.put_idx = i
                    c = signed(d.args[1].con.value, self.bits)
                    if d.op.startswith("Iop_Sub"):
                        c = -c
                    self.frame_delta = c
                    return

    def after_put(self, i):
        """is statement i executed after sp == frame sp?"""
        if not self.contains_put:
            return True                      # prologue ran before this block
        return (self.put_idx is not None and i > self.put_idx)

    def _lin(self, exp, depth=0, after_put=False):
        if depth > 12:
            return (0, {}, True, False)
        if isinstance(exp, pyvex.expr.Const):
            return lin_const(exp.con.value, self.bits)
        if isinstance(exp, pyvex.expr.RdTmp):
            if exp.tmp in self.memo:
                return self.memo[exp.tmp]
            return (0, {}, True, False)
        if isinstance(exp, pyvex.expr.Get):
            if exp.offset == self.sp_off:
                if after_put or not self.contains_put or not self.frame_delta:
                    return (0, {}, False, True)          # frame sp
                return (-self.frame_delta, {}, False, True)  # incoming sp
            return (0, {exp.offset: 1}, False, False)
        if isinstance(exp, pyvex.expr.Binop):
            op = exp.op
            if op in ADD:
                return merge(self._lin(exp.args[0], depth + 1, after_put),
                             self._lin(exp.args[1], depth + 1, after_put))
            if op in SUB:
                return merge(self._lin(exp.args[0], depth + 1, after_put),
                             neg(self._lin(exp.args[1], depth + 1, after_put)))
            return (0, {}, True, False)
        return (0, {}, True, False)

    def _number(self):
        for i, st in enumerate(self.irsb.statements):
            if isinstance(st, pyvex.stmt.WrTmp):
                self.memo[st.tmp] = self._lin(st.data, 0, self.after_put(i))

    def rhs_linear(self, data, i):
        """linearize a data/address expression occurring at statement index i."""
        return self._lin(data, 0, self.after_put(i))


def scan_function(vs, name, addr, fsize):
    """Run BlockV over every block of one function and collect facts."""
    facts = {"frame": None, "ra_slot": None, "gp": None,
             "calls": [], "arg0_frame": [], "names": []}
    blocks = vs.function_blocks(addr, fsize)
    if not blocks:
        return facts
    prologue = min(blocks)
    frame_delta = 0
    try:
        pirsb = vs.proj.factory.block(prologue).vex
    except Exception:
        pirsb = None
    if pirsb is not None:
        frame_delta = BlockV(pirsb, vs.sp, vs.bits, 0, True).frame_delta
    gp = None
    ra_slot = None
    frame = None
    arg0_pushes = []
    calls = []
    mem_frame = {}          # frame-relative K -> constant (store-then-load)
    # numeric SSA per block: reg ints and tmp ints are block scoped for values,
    # but stack slots persist across the whole function in address order.
    for ba in sorted(blocks):
        try:
            irsb = vs.proj.factory.block(ba).vex
        except Exception:
            continue
        cp = (ba == prologue)
        bv = BlockV(irsb, vs.sp, vs.bits, frame_delta if frame_delta else 0, cp)
        if frame is None and bv.frame_delta:
            frame = -bv.frame_delta
        # ---- numeric pass for this block
        nval = {}           # tmp -> int (pure const)
        gotn = {}           # tmp -> import name (tmp = Load from GOT slot)
        reg = {}            # reg_off -> int (constant reg content)
        loadaddr = {}       # tmp -> addr expression handle for Load (later)
        # MIPS PIC prologue computes $gp as (_gp - func) + $t9, where $t9 holds the
        # function's own runtime address at entry. Seed it so $gp resolves to the
        # real (rebased) _gp and GOT-slot calls can be named; without this every
        # call in a shared object stays anonymous.
        if cp and vs.t9 is not None:
            reg[vs.t9] = addr

        def numeric(exp):
            """return ('v', int) | ('g', name) | None"""
            if isinstance(exp, pyvex.expr.Const):
                return ("v", signed(exp.con.value, vs.bits))
            if isinstance(exp, pyvex.expr.RdTmp):
                if exp.tmp in nval and nval[exp.tmp] is not None:
                    return ("v", nval[exp.tmp])
                if exp.tmp in gotn:
                    return ("g", gotn[exp.tmp])
                return None
            if isinstance(exp, pyvex.expr.Get):
                return ("v", reg[exp.offset]) if exp.offset in reg else None
            if isinstance(exp, pyvex.expr.Binop) and (exp.op in ADD | SUB):
                a = numeric(exp.args[0]); b = numeric(exp.args[1])
                if a and a[0] == "v" and b and b[0] == "v":
                    return ("v", a[1] + b[1] if exp.op in ADD else a[1] - b[1])
                return None
            return None

        for i, st in enumerate(irsb.statements):
            if isinstance(st, pyvex.stmt.WrTmp):
                d = st.data
                if isinstance(d, pyvex.expr.Load):
                    # load from GOT slot => name; load from frame slot => const
                    an = numeric(d.addr)
                    if an and an[0] == "v" and an[1] is not None:
                        a = an[1] & 0xffffffff
                        g = vs.got.get(a)
                        if g:
                            gotn[st.tmp] = normf(g)
                            loadaddr[st.tmp] = a
                            continue
                        m = mem_frame.get(a - (gp or 0)) if gp else None
                        if m is not None:
                            nval[st.tmp] = m
                        continue
                    # frame-slot load: addr is frame-relative
                    lc, lco, lun, lfr = bv.rhs_linear(d.addr, i)
                    if not lun and not lco and lfr and lc in mem_frame:
                        nval[st.tmp] = mem_frame[lc]
                    continue
                # not a load: numeric const through pure arithmetic
                v = numeric(d)
                if v and v[0] == "v":
                    nval[st.tmp] = v[1]
                # also capture GOT-slot loads expressed as gp+imm linear later
                if v and v[0] == "g":
                    gotn[st.tmp] = v[1]
            elif isinstance(st, pyvex.stmt.Put):
                v = numeric(st.data)
                if v and v[0] == "v":
                    reg[st.offset] = v[1]
                else:
                    reg.pop(st.offset, None)
            elif isinstance(st, pyvex.stmt.Store):
                dv = numeric(st.data)
                # frame-relative constant store -> mem_frame
                lc, lco, lun, lfr = bv.rhs_linear(st.addr, i)
                if not lun and not lco and lfr and dv and dv[0] == "v":
                    mem_frame[lc] = dv[1]
                else:
                    an = numeric(st.addr)
                    if an and an[0] == "v" and dv and dv[0] == "v":
                        pass  # absolute store; not needed for our motifs
        # ---- fact collection using bv.memo (linear) ----
        for i, st in enumerate(irsb.statements):
            if (isinstance(st, pyvex.stmt.Put) and vs.gp_off is not None and
                    st.offset == vs.gp_off and gp is None and
                    isinstance(st.data, pyvex.expr.Const)):
                gp = st.data.con.value
            if isinstance(st, pyvex.stmt.Store) and ra_slot is None:
                _, dco, dun, _ = bv.rhs_linear(st.data, i)
                if not dun and set(dco) == {vs.ra} and dco.get(vs.ra) == 1:
                    ac, aco, aun, afr = bv.rhs_linear(st.addr, i)
                    if not aun and not aco and afr:
                        ra_slot = ac
            if isinstance(st, pyvex.stmt.Put) and vs.argregs and st.offset == vs.argregs[0]:
                c, coeff, unk, fr = bv.rhs_linear(st.data, i)
                if not unk and not coeff and fr:
                    arg0_pushes.append((ba, c))
        # ---- call naming ----
        if str(irsb.jumpkind).startswith("Ijk_Call"):
            nxt = irsb.next
            nm = None
            if isinstance(nxt, pyvex.expr.Const):
                nm = vs.resolve(nxt.con.value)
            elif isinstance(nxt, pyvex.expr.RdTmp):
                if nxt.tmp in gotn:
                    nm = gotn[nxt.tmp]
                elif nxt.tmp in nval and nval[nxt.tmp] is not None:
                    nm = vs.resolve(nval[nxt.tmp] & 0xffffffff)
                else:
                    # linear fallback (gp+imm direct without memory reload)
                    lin = bv.memo.get(nxt.tmp)
                    if lin is not None:
                        c, coeff, unk, fr = lin
                        if not unk and not coeff:
                            nm = vs.resolve(c)
                        elif (not unk and vs.gp_off is not None and
                              set(coeff) == {vs.gp_off} and gp):
                            slot = gp + c
                            nm = vs.got.get(slot & 0xffffffff) or vs.got.get(slot)
            calls.append((irsb.addr, nm))
    facts["frame"] = frame
    facts["gp"] = gp
    facts["ra_slot"] = ra_slot
    facts["arg0_frame"] = arg0_pushes
    facts["calls"] = calls
    nm2 = []
    for (_, n) in calls:
        if n and n not in nm2:
            nm2.append(n)
    facts["names"] = nm2
    return facts
