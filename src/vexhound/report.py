"""
report.py - build a self-contained interactive HTML report for `vexhound scan`.

The report reuses the objects the deep pipeline already builds (RuleEngine ->
CandidateBuilder -> SummaryEngine/TaintEngine, plus the OverflowProver findings),
so nothing is recomputed. For each finding it draws a sink-to-source graph: how
attacker data reaches the dangerous sink, read backwards from the sink through the
function(s) to the input source(s). A "whole application graph" view shows the full
call graph with the vulnerable branches highlighted. Every node carries a binary
address; clicking one shows that location as VEX IR, Capstone assembly, and
(best-effort) Ghidra pseudo-code, with the source/sink calls and the tainted
argument highlighted.

The taint engine is a forward may-analysis, not a backward slicer, so the graph is
the recorded forward flow shown backwards, enriched with the call-graph path, the
taint provenance, and the prover's dest/room/size. The UI says as much.
"""
import base64
import collections
import html
import json
import os
import re
import subprocess
import tempfile
from collections import Counter

from .vex import normf

# layout constants (pixels); node coordinates are computed here and drawn as-is
_COLW, _ROWH, _NW, _NH, _PADX, _PADY = 210, 78, 176, 46, 40, 30
# smaller cells for the dense whole-application graph
_ACOLW, _AROWH, _ANW, _ANH = 158, 30, 132, 22


def _code_for(proj, addr):
    """VEX IR + Capstone assembly for the block at addr. Ghidra is filled later."""
    try:
        ir = str(proj.factory.block(addr).vex)
    except Exception as e:
        ir = f"(IR unavailable: {type(e).__name__})"
    try:
        asm = "\n".join(f"{i.address:#010x}:  {i.mnemonic:<8} {i.op_str}"
                        for i in proj.factory.block(addr).capstone.insns)
    except Exception as e:
        asm = f"(assembly unavailable: {type(e).__name__})"
    return {"ir": ir, "asm": asm, "ghidra": None}


def _source_site(eng, func_addr, source_name):
    """Address of the block that calls `source_name` inside func_addr, if any."""
    for block, nm in (eng._srcs_at.get(func_addr) or {}).items():
        if nm and normf(nm) == normf(source_name):
            return block
    return None


def _argreg_name(vs, tainted_arg):
    """Register name carrying the tainted argument (e.g. arg0 -> a0 on MIPS)."""
    for tok in (tainted_arg or "").split(","):
        tok = tok.strip()
        if tok.startswith("arg") and tok[3:].isdigit():
            idx = int(tok[3:])
            if idx < len(vs.argregs):
                off = vs.argregs[idx]
                for nm, (o, _s) in vs.nm2off.items():
                    if o == off:
                        return nm
    return ""


def _finding_highlight(row, vs, flow_vars=None):
    """Terms to highlight in the code views for this finding's data flow:
    source primitives (green), the sink (red), the tainted argument register in
    IR/ASM (blue), and the C variables that carry the tainted value into the sink
    (amber) so the data flow itself is lit up, not just the call names."""
    return {
        "sink": row["sink"],
        "sources": [s for s in (row.get("sources") or "").split(",") if s],
        "reg": _argreg_name(vs, row.get("tainted_arg", "")),
        "flow": list(flow_vars or []),
    }


# C keywords / Ghidra pseudo-type tokens that are never the tainted "variable".
_C_NOISE = {
    "char", "int", "uint", "void", "byte", "bool", "short", "long", "ulong",
    "ushort", "code", "float", "double", "true", "false", "NULL", "sizeof",
    "if", "else", "for", "while", "do", "switch", "case", "break", "continue",
    "goto", "return", "struct", "union", "enum", "const", "unsigned", "signed",
    "undefined", "undefined1", "undefined2", "undefined3", "undefined4",
    "undefined8", "extraout", "unaff", "in", "register", "static",
}


def _idents(s):
    return set(re.findall(r"[A-Za-z_]\w*", s or ""))


def _split_call_args(text, open_idx):
    """Given the index of a call's '(', return its top-level argument strings."""
    depth, cur, args, i, n = 0, [], [], open_idx, len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return args
        elif c == "," and depth == 1:
            args.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    return None


def _c_call_args(text, name):
    """All argument lists for calls to `name` in the decompiled C, handling both
    `name(...)` and Ghidra's `(*(code *)PTR_name_hhhh)(...)` indirect form."""
    out = []
    pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])")
    for m in pat.finditer(text):
        j = text.find("(", m.end(), m.end() + 80)
        if j < 0:
            continue
        args = _split_call_args(text, j)
        if args:
            out.append(args)
    return out


def _line_at(dec, addr):
    """Index of the decompiled line whose address best matches `addr` (the greatest
    line address <= addr, falling back to the nearest mapped line)."""
    lines = (dec.get("text") or "").split("\n")
    addrs = (dec.get("addrs") or [])[:len(lines)]
    best_i, best_a = None, None
    for i, a in enumerate(addrs):
        if a is not None and a <= addr and (best_a is None or a > best_a):
            best_a, best_i = a, i
    if best_i is None:
        cand = [(abs(a - addr), i) for i, a in enumerate(addrs) if a is not None]
        if cand:
            best_i = min(cand)[1]
    return best_i


def _focal(window):
    """The marked focal line of a _gwindow() window, without its marker prefix."""
    for ln in (window or "").split("\n"):
        if ln.startswith("▸"):
            return ln[2:]
    return ""


def _flow_vars(sink_win, src_wins, row):
    """Identifiers to highlight as the tainted data: the variable(s) passed as the
    sink's tainted argument, plus any variable shared between the sink call line and
    a source call line (the value literally carried from source to sink, e.g. the
    read() buffer that reappears in sprintf())."""
    sfocal = _focal(sink_win)
    if not sfocal:
        return []
    idxs = [int(t[3:]) for t in (row.get("tainted_arg") or "").split(",")
            if t.strip().startswith("arg") and t.strip()[3:].isdigit()]
    region = "\n".join(l[2:] for l in sink_win.split("\n") if l[:2] in ("▸ ", "  "))
    tainted = set()
    for args in (_c_call_args(region, row["sink"]) or [])[:1]:
        for k in (idxs or range(len(args))):
            if k < len(args):
                tainted |= _idents(args[k])
    src_idents = set()
    for w in src_wins:
        src_idents |= _idents(_focal(w))
    connecting = _idents(sfocal) & src_idents
    flow = (tainted | connecting)
    return sorted(v for v in flow if v not in _C_NOISE and not v.startswith("PTR_"))[:6]


def _call_line(dec, addr, name=None, ctx=11):
    """Absolute index of the C line for the call at `addr`: anchor on the address,
    then snap to the nearby line that actually contains `name`, so we land on the
    real call, not the block's setup code."""
    lines = (dec.get("text") or "").split("\n")
    focal = _line_at(dec, addr)
    if focal is None:
        return None
    if name:
        pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])")
        near = [j for j in range(max(0, focal - 2 * ctx), min(len(lines), focal + 2 * ctx + 1))
                if pat.search(lines[j])]
        if near:
            focal = min(near, key=lambda j: abs(j - focal))
    return focal


def _gwindow(dec, addr=None, name=None, focal=None, ctx=5):
    """A focused window of a decompiled function's C around a line (the call at
    `addr`/`name`, or an explicit `focal` index), with the focal line marked. A
    tight window (a few lines each side) keeps every card readable and stops the
    same function being repeated at length across a chain of steps."""
    lines = (dec.get("text") or "").split("\n")
    if focal is None and addr is not None:
        focal = _call_line(dec, addr, name, 11)   # wide search to find the call...
    if focal is None:
        return "\n".join(lines[: ctx * 2])
    lo, hi = max(0, focal - ctx), min(len(lines), focal + ctx + 1)  # ...tight window to show it
    return "\n".join(("▸ " if i == focal else "  ") + lines[i] for i in range(lo, hi))


def _circ(n):
    return chr(0x2460 + n - 1) if 1 <= n <= 20 else f"{n}."


def _prop_steps(dec, flow, src_idxs, sink_idx, addrs, lines):
    """Lines between the source(s) and the sink that reference a tainted variable:
    the intra-procedural hops the data takes on its way to the sink. Thinned to a
    few so the chain stays readable; only lines with a machine address are kept."""
    if not (dec and flow and src_idxs and sink_idx is not None and sink_idx > min(src_idxs)):
        return []
    pats = [re.compile(r"(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])") for v in flow]
    cand = []
    for j in range(min(src_idxs) + 1, sink_idx):
        s = lines[j].strip()
        if not s or s in ("{", "}"):
            continue
        a = addrs[j] if j < len(addrs) else None
        if a is not None and any(p.search(lines[j]) for p in pats):
            cand.append((j, a, s))
    # keep steps far enough apart that their code windows do not overlap, so the
    # chain shows DISTINCT hops instead of the same lines repeated on every card.
    MIN_GAP = 12                            # ~ the window height (2*ctx+1)
    kept = []
    for c in cand:
        if not kept or c[0] - kept[-1][0] >= MIN_GAP:
            kept.append(c)
        if len(kept) >= 4:
            break
    return kept


def _finding_graph(row, eng, pf, code, decomp, containing):
    """The data-flow chain for one finding, as code cards, top to bottom: the source
    call site(s), then each intra-procedural hop that carries the tainted value, then
    the sink call site. Each card's IR/ASM is that block, its Ghidra is a focused
    window of the enclosing function around that exact line, with the flow highlighted.
    Cards are sized to fit their code so the canvas pans/zooms as one graph."""
    func_addr = eng.name2addr.get(row["function"])
    sources = [s for s in (row.get("sources") or "").split(",") if s]
    block_addr = int(row["addr"], 16)
    fnd = pf.get(row["addr"], {})
    site = fnd.get("site", row["addr"])
    fa = containing(block_addr)
    dec = decomp.get(hex(fa)) if fa is not None else None
    CW, GAPX, GAPY = 540, 44, 70
    nodes, edges = [], []

    def add_code(a, name=None, focal=None):
        if a is None:
            return None
        key = hex(a)
        if key not in code:
            entry = _code_for(eng.vs.proj, a)
            d = decomp.get(hex(containing(a))) if containing(a) is not None else None
            if d:
                entry["ghidra"] = _gwindow(d, addr=a, name=name, focal=focal)
            code[key] = entry
        return key

    def card_h(key):
        entry = code.get(key) or {}
        n = 1
        for v in ("ghidra", "asm", "ir"):
            if entry.get(v):
                n = max(n, entry[v].count("\n") + 1)
        return 40 + min(n, 80) * 15 + 12    # fit the code; no card-local scroll

    # sources across the top
    num = 0
    src_ids, src_keys, max_src_h = [], [], 0
    for i, s in enumerate(sources):
        num += 1
        sa = _source_site(eng, func_addr, s) if func_addr is not None else None
        key = add_code(sa, s)
        src_keys.append(key)
        h = card_h(key) if key else 62
        max_src_h = max(max_src_h, h)
        sid = f"src{i}"
        src_ids.append(sid)
        nodes.append({"id": sid, "kind": "source",
                      "label": f"{_circ(num)} source: {s}",
                      "sub": (f"{s} call @ {hex(sa)}" if sa is not None else "external input"),
                      "addr": (hex(sa) if sa is not None else None),
                      "x": _PADX + i * (CW + GAPX), "y": _PADY, "w": CW, "h": h})

    # sink window (needed to compute the flow variables)
    sink_key = add_code(block_addr, row["sink"])
    sink_win = (code.get(sink_key) or {}).get("ghidra")
    src_wins = [(code.get(k) or {}).get("ghidra") for k in src_keys if k]
    flow = _flow_vars(sink_win, src_wins, row)

    # propagation hops that carry the tainted value from source to sink
    prop = []
    if dec:
        lines = (dec.get("text") or "").split("\n")
        addrs = dec.get("addrs") or []
        sink_idx = _call_line(dec, block_addr, row["sink"])
        src_idxs = [ci for s in sources
                    for sa in [_source_site(eng, func_addr, s) if func_addr is not None else None]
                    if sa is not None
                    for ci in [_call_line(dec, sa, s)] if ci is not None]
        prop = _prop_steps(dec, flow, src_idxs, sink_idx, addrs, lines)

    # lay out the column: propagation steps, then the sink
    col_y = _PADY + (max_src_h + GAPY if sources else 0)
    col_ids = []
    for (j, a, text) in prop:
        num += 1
        key = add_code(a, focal=j)
        h = card_h(key)
        pid = f"p{len(col_ids)}"
        col_ids.append(pid)
        nodes.append({"id": pid, "kind": "prop",
                      "label": f"{_circ(num)} carries {', '.join(flow[:2])}",
                      "sub": text[:70], "addr": hex(a),
                      "x": _PADX, "y": col_y, "w": CW, "h": h})
        col_y += h + GAPY

    num += 1
    sh = card_h(sink_key)
    sink_sub = (f"in {row['function']}  ·  dest {fnd['dest']} room {fnd.get('room', '?')} "
                f"size {fnd.get('size', '?')}" if fnd.get("dest")
                else f"in {row['function']}  ·  {row['cls']} arg {row.get('tainted_arg', '?')}")
    nodes.append({"id": "sink", "kind": "sink",
                  "label": f"{_circ(num)} sink: {row['sink']}@{site}", "sub": sink_sub,
                  "addr": hex(block_addr), "x": _PADX, "y": col_y, "w": CW, "h": sh,
                  "severity": row.get("severity", "-"), "verdict": row.get("verdict", "")})
    col_ids.append("sink")

    # edges: sources -> first column node; then down the column
    first = col_ids[0]
    lbl = ("taints " + row.get("tainted_arg", "")).strip()
    for sid in src_ids:
        edges.append({"from": sid, "to": first, "label": lbl, "kind": "taint"})
    carry = ("carries " + flow[0]) if flow else ""
    for i in range(len(col_ids) - 1):
        edges.append({"from": col_ids[i], "to": col_ids[i + 1], "label": carry, "kind": "taint"})

    width = max(_PADX + max(1, len(sources)) * (CW + GAPX), _PADX + CW + _PADX)
    height = col_y + sh + _PADY
    return nodes, edges, width, height, flow


def _app_graph(engine, rows):
    """Whole-program call graph, laid out by BFS layers from ENTRY, with the
    functions on any path to a sink marked vulnerable and those edges highlighted."""
    cb = engine.cb
    eng = cb.eng
    g = cb.g
    funcs = eng.funcs
    if g is None:
        return {"nodes": [], "edges": [], "w": 0, "h": 0}

    vuln, path_nodes, vuln_edges = set(), set(), set()
    for r in rows:
        fa = eng.name2addr.get(r["function"])
        if fa is not None:
            vuln.add(fa)
        names = (r.get("path") or "").split(" -> ")
        addrs = [eng.name2addr.get(n) for n in names]
        prev = "ENTRY"
        for a in addrs:
            if a is None:
                continue
            path_nodes.add(a)
            vuln_edges.add((prev, a))
            prev = a

    layer = {"ENTRY": 0}
    dq = collections.deque(["ENTRY"])
    while dq:
        u = dq.popleft()
        for v in g.successors(u):
            if v not in layer:
                layer[v] = layer[u] + 1
                dq.append(v)
    maxl = max(layer.values()) if layer else 0

    allnodes = ["ENTRY"] + sorted(funcs)
    bylayer = collections.defaultdict(list)
    for a in allnodes:
        bylayer[layer.get(a, maxl + 1)].append(a)

    # place each layer left to right; wrap tall layers (e.g. the pile of library
    # functions unreachable from ENTRY) into sub-columns so height stays bounded.
    rows_max = 32
    nodes, xcur = [], _PADX
    for L in sorted(bylayer):
        items = bylayer[L]
        for i, a in enumerate(items):
            x = xcur + (i // rows_max) * _ACOLW
            y = _PADY + (i % rows_max) * _AROWH
            if a == "ENTRY":
                nodes.append({"id": "ENTRY", "label": "ENTRY", "addr": None,
                              "x": x, "y": y, "w": _ANW, "h": _ANH, "kind": "entry"})
            else:
                kind = "vuln" if a in vuln else ("path" if a in path_nodes else "plain")
                nodes.append({"id": hex(a), "label": funcs[a][0], "addr": hex(a),
                              "x": x, "y": y, "w": _ANW, "h": _ANH, "kind": kind})
        xcur += max(1, (len(items) + rows_max - 1) // rows_max) * _ACOLW + 26
    edges = []
    for u, v in g.edges():
        uid = u if u == "ENTRY" else hex(u)
        vid = v if v == "ENTRY" else hex(v)
        edges.append({"from": uid, "to": vid,
                      "kind": "vuln" if (u, v) in vuln_edges else "plain"})
    w = xcur + _ANW
    h = _PADY + min(rows_max, max((len(v) for v in bylayer.values()), default=1)) * _AROWH + _PADY
    return {"nodes": nodes, "edges": edges, "w": w, "h": h}


def _stages(engine, rows, symbolic_results):
    """Pipeline-stage summary derived from the already-built engine objects."""
    eng = engine.cb.eng
    roles = Counter(S.role.split("[")[0] for S in eng.summaries.values())
    seen, flows = set(), []
    for fl in eng.flows:
        k = (fl["func"], fl["source"], fl["sink"], fl["cls"])
        if k not in seen:
            seen.add(k)
            fn = eng.funcs.get(fl["func"], ("?",))[0]
            flows.append(f"{fl['source']} -> {fl['sink']}  in {fn} @ {fl['at']:#x}")
    verdicts = Counter(r["verdict"] for r in rows)
    pv = Counter(str(f.get("verdict", "?")) for f in engine.pf.values())
    return [
        {"id": "load", "name": "Load & CFG", "stat": f"{len(eng.vs.functions())} functions",
         "items": [f"arch {engine.arch}"]},
        {"id": "ir", "name": "Lift to VEX IR", "stat": "per-block, on demand",
         "items": ["each basic block is lifted to VEX IR and value-numbered"]},
        {"id": "classify", "name": "Classify",
         "stat": f"{roles.get('SOURCE', 0)} source · {roles.get('SINK', 0)} sink "
                 f"· {roles.get('PROPAGATOR', 0)} prop · {roles.get('NEUTRAL', 0)} neutral",
         "items": [f"{r}: {roles.get(r, 0)}" for r in ("SOURCE", "SINK", "PROPAGATOR", "NEUTRAL")]},
        {"id": "taint", "name": "Taint flows", "stat": f"{len(flows)} source-to-sink flows",
         "items": flows[:60]},
        {"id": "candidates", "name": "Candidates", "stat": f"{len(engine.cands)} ranked",
         "items": [f"#{c['rank']} [{c['severity']}] {c['cls']} {c['sink']}@{c['addr']} {c['function']}"
                   for c in engine.cands[:60]]},
        {"id": "prove", "name": "Prove geometry",
         "stat": f"{pv.get('OVERFLOW', 0)} overflow · {pv.get('SAFE', 0)} safe · "
                 f"{pv.get('UNMODELED', 0) + pv.get('NOT_STACK', 0)} unmodeled",
         "items": [f"[{f.get('verdict', '?')}] dest={f.get('dest')} "
                   f"room={f.get('room')} size={f.get('size')}"
                   for f in list(engine.pf.values())[:60]]},
        {"id": "verdict", "name": "Verdict",
         "stat": f"{verdicts.get('CONFIRMED', 0)} confirmed · "
                 f"{verdicts.get('NEEDS_SYMBOLIC', 0)} needs-symbolic · "
                 f"{verdicts.get('REFUTED', 0)} refuted",
         "items": [f"[{r['verdict']}] {r['cls']} {r['sink']}@{r['addr']} {r['function']}" for r in rows]},
        {"id": "verify", "name": "Symbolic",
         "stat": (f"{len(symbolic_results)} confirmed symbolically" if symbolic_results
                  else "(opt-in; pass --confirm)"),
         "items": [f"[{v['result']}] {v['sink']}@{v['addr']} {v['function']}  {v.get('reason', '')}"
                   for v in symbolic_results.values()]},
        {"id": "emulate", "name": "Emulate", "stat": "(opt-in · vexhound emulate)",
         "items": ["synthesizes a PoV from the geometry, runs the binary under QEMU, watches for the crash"]},
    ]


def _run_symbolic(engine, rows, path):
    """Opt-in: symbolically confirm the NEEDS_SYMBOLIC rows. Returns {addr: result}."""
    from . import symbolic
    proj = engine.cb.eng.vs.proj
    out = {}
    for r in rows:
        if r["verdict"] != "NEEDS_SYMBOLIC":
            continue
        sym = proj.loader.find_symbol(r["function"])
        if sym is None:
            continue
        ta = None
        for tok in r["tainted_arg"].split(","):
            if tok.startswith("arg") and tok[3:].isdigit():
                ta = int(tok[3:])
                break
        try:
            res = symbolic.confirm(path, sym.rebased_addr, int(r["addr"], 16), ta, budget_s=30)
        except Exception as e:
            res = {"result": "ERROR", "reason": str(e)[:120]}
        res.update(sink=r["sink"], addr=r["addr"], function=r["function"])
        out[r["addr"]] = res
    return out


def find_ghidra_home(explicit=None):
    """Locate a Ghidra install (a directory with support/analyzeHeadless): an
    explicit path first, then $GHIDRA_HOME, then the usual install locations. This
    means the report's pseudo-code works with no setup when Ghidra is installed,
    instead of depending on an env var that a non-login shell never sees."""
    import glob
    cands = [explicit, os.environ.get("GHIDRA_HOME")]
    home = os.path.expanduser("~")
    bases = [os.path.join(home, "Tools", "ghidra"), os.path.join(home, "ghidra"),
             os.path.join(home, "Tools"), home, "/opt", "/opt/ghidra",
             "/usr/share", "/usr/local", "/usr/local/share", "/Applications"]
    for base in bases:
        for pat in ("ghidra_*_PUBLIC", "ghidra_*", "ghidra"):
            cands += sorted(glob.glob(os.path.join(base, pat)), reverse=True)
    seen = set()
    for c in cands:
        if not c or c in seen:
            continue
        seen.add(c)
        if os.path.exists(os.path.join(c, "support", "analyzeHeadless")):
            return c
    return None


def _ghidra_decompile(path, func_addrs, ghidra_home):
    """Best-effort: decompile the given function entries with headless Ghidra."""
    headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
                                          "tools", "ghidra_scripts"))
    if not os.path.exists(headless) or not func_addrs:
        return {}
    work = tempfile.mkdtemp(prefix="vexhound_ghidra_")
    out_file = os.path.join(work, "decomp.tsv")
    addr_arg = ",".join(hex(a) for a in sorted(set(func_addrs)) if a is not None)
    try:
        subprocess.run(
            [headless, work, "proj", "-import", path, "-scriptPath", script,
             "-postScript", "DecompFuncs.java", out_file, addr_arg, "-deleteProject"],
            capture_output=True, timeout=600, check=False)
    except Exception:
        return {}
    result = {}
    try:
        with open(out_file) as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2 or not parts[1]:
                    continue
                text = base64.b64decode(parts[1]).decode("utf-8", "replace")
                addrs = []
                if len(parts) >= 3 and parts[2]:
                    try:
                        arr = json.loads(base64.b64decode(parts[2]).decode("utf-8", "replace"))
                        addrs = [int(a, 16) if isinstance(a, str) else None for a in arr]
                    except Exception:
                        addrs = []
                result[parts[0]] = {"text": text, "addrs": addrs}
    except Exception:
        pass
    return result


def build_model(engine, path, run_symbolic=False, ghidra_home=None):
    """Assemble the report model dict from an already-built RuleEngine."""
    eng = engine.cb.eng
    vs = eng.vs
    rows = engine.run()
    symbolic_results = _run_symbolic(engine, rows, path) if run_symbolic else {}

    # Decompile up front so each node can carry a focused pseudo-code window (and
    # the tainted-variable highlight is computed from the real C, not guessed).
    decomp = {}
    if ghidra_home:
        func_addrs = [eng.name2addr.get(r["function"]) for r in rows]
        decomp = _ghidra_decompile(path, [a for a in func_addrs if a is not None], ghidra_home)

    funcs_sorted = sorted((a, s) for a, (n, s) in eng.funcs.items())

    def containing(a):
        for fa, span in funcs_sorted:
            if fa <= a < fa + span:
                return fa
        return None

    code, findings = {}, []
    for r in rows:
        nodes, edges, w, h, flow = _finding_graph(r, eng, engine.pf, code, decomp, containing)
        sym = symbolic_results.get(r["addr"])
        # Alternative call chains: a sink function is often reachable from more than
        # one attacker-facing handler. Show the extras as "also reachable from ..."
        # (bounded call-graph enumeration; the primary chain stays r["path"]).
        fa = eng.name2addr.get(r["function"])
        paths_alt = []
        if fa is not None:
            chains, _reach = engine.cb._paths_to(fa, k=3)
            paths_alt = [" -> ".join(c) for c in chains[1:] if c]
        findings.append({
            "id": r["addr"], "cls": r["cls"], "sink": r["sink"], "addr": r["addr"],
            "site": engine.pf.get(r["addr"], {}).get("site", r["addr"]),
            "function": r["function"], "verdict": r["verdict"],
            "severity": r.get("severity", "-"), "score": r.get("score", 0),
            "reason": r.get("evidence", ""), "path": r.get("path", ""),
            "paths_alt": paths_alt,
            "sources": r.get("sources", ""), "flow": flow,
            "symbolic": (f"{sym['result']} - {sym.get('reason', '')}" if sym else None),
            "highlight": _finding_highlight(r, vs, flow),
            "graph": {"nodes": nodes, "edges": edges, "w": w, "h": h},
        })

    return {
        "binary": os.path.basename(path), "path": path, "arch": engine.arch,
        "mitigations": getattr(vs, "mitigations", {}) or {},
        "has_ghidra": bool(ghidra_home) and any(c.get("ghidra") for c in code.values()),
        "stages": _stages(engine, rows, symbolic_results),
        "findings": findings, "appgraph": _app_graph(engine, rows), "code": code,
    }


def render_html(model):
    """Render the model as a single self-contained HTML string (no CDN)."""
    payload = json.dumps(model, ensure_ascii=False)
    title = html.escape("VexHound report: " + model["binary"])
    return _TEMPLATE.replace("/*__TITLE__*/", title).replace('"__MODEL__"', payload)


def write_report(out_path, model):
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(render_html(model))
    return out_path


_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>/*__TITLE__*/</title>
<style>
  :root{
    --bg:#ffffff; --panel:#f6f6f6; --ink:#1b1b1b; --mut:#6a6a6a; --rule:#d6d6d6;
    --red:#b00020; --redbg:#fdecec; --amber:#8a6d00; --amberbg:#fbf3d6;
    --green:#136c3a; --greenbg:#e7f4ec; --blue:#0b4fb0; --bluebg:#e6eefb;
    --sans:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --mono:"DejaVu Sans Mono",Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 var(--sans)}
  header{display:flex;align-items:baseline;gap:12px;padding:8px 14px;border-bottom:1px solid var(--rule)}
  header h1{font-size:15px;margin:0;font-weight:700}
  header .meta{color:var(--mut);font-size:12.5px}
  .stages{display:flex;overflow-x:auto;border-bottom:1px solid var(--rule);background:var(--panel)}
  .stage{flex:1 0 auto;min-width:150px;padding:7px 12px;border-right:1px solid var(--rule);cursor:pointer}
  .stage:hover{background:#eee}
  .stage.active{background:#fff;box-shadow:inset 0 -2px 0 var(--blue)}
  .stage b{display:block;font-size:12px;font-weight:600}
  .stage span{color:var(--mut);font-size:11.5px}
  .wrap{display:grid;grid-template-columns:300px 1fr;height:calc(100vh - 94px)}
  @media (max-width:820px){.wrap{grid-template-columns:1fr;height:auto}}
  .side{border-right:1px solid var(--rule);overflow:auto;background:var(--panel)}
  .side h2{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin:0;padding:9px 12px 3px}
  .f{padding:7px 12px;border-bottom:1px solid var(--rule);cursor:pointer}
  .f:hover{background:#eee}
  .f.active{background:#fff;box-shadow:inset 3px 0 0 var(--red)}
  .f .t{font-family:var(--mono);font-size:12.5px}
  .f .v{font-size:11px;color:var(--mut);margin-top:2px}
  .badge{display:inline-block;font-size:10px;padding:1px 5px;border:1px solid var(--rule);border-radius:2px;margin-right:3px}
  .b-CRITICAL,.b-CONFIRMED{background:var(--redbg);color:var(--red);border-color:#e7b7b7}
  .b-HIGH,.b-NEEDS_SYMBOLIC{background:var(--amberbg);color:var(--amber);border-color:#e2cf8a}
  .b-REFUTED,.b-MEDIUM,.b-LOW{background:var(--greenbg);color:var(--green);border-color:#b6dcc3}
  .main{display:flex;flex-direction:column;min-width:0}
  .toolbar{display:flex;gap:8px;align-items:center;padding:6px 10px;border-bottom:1px solid var(--rule);background:var(--panel);flex-wrap:wrap}
  .toolbar button{font:12.5px var(--sans);padding:4px 10px;border:1px solid var(--rule);background:#fff;cursor:pointer;border-radius:2px}
  .toolbar button.on{background:var(--ink);color:#fff;border-color:var(--ink)}
  .nvwrap{display:flex;gap:5px;align-items:center;margin-left:8px;padding-left:10px;border-left:1px solid var(--rule)}
  .nvlab{color:var(--mut);font-size:11.5px}
  .nvbtn{font:12px var(--sans);padding:3px 9px;border:1px solid var(--rule);background:#fff;cursor:pointer;border-radius:2px}
  .nvbtn.on{background:var(--blue);color:#fff;border-color:var(--blue)}
  .toolbar .legend{margin-left:auto;color:var(--mut);font-size:11.5px}
  .legend i{display:inline-block;width:10px;height:10px;border:1px solid var(--rule);vertical-align:-1px;margin:0 3px 0 8px}
  .graphwrap{flex:1;overflow:hidden;position:relative;background:#fbfbfb}
  .hint{position:absolute;top:6px;left:10px;color:var(--mut);font-size:11.5px;pointer-events:none;background:rgba(255,255,255,.72);padding:1px 5px;border-radius:2px}
  .chains{position:absolute;top:26px;left:10px;right:10px;color:var(--mut);font-size:11.5px;
    background:rgba(255,255,255,.86);padding:2px 7px;border-radius:2px;border:1px solid var(--rule);
    max-width:70%;line-height:1.5;pointer-events:none}
  .chains b{color:var(--ink);font-weight:600}
  .chains .alt{color:var(--blue)}
  .chains code{font-family:var(--mono);font-size:11px}
  svg{width:100%;height:100%;cursor:grab}
  svg.drag{cursor:grabbing}
  .node rect{stroke-width:1.4;fill:#fff}
  .node.func rect,.node.plain rect{stroke:#9a9a9a}
  .node.entry rect{stroke:#555;fill:var(--panel)}
  .node.source rect{stroke:var(--green);fill:var(--greenbg)}
  .node.path rect{stroke:var(--amber);fill:var(--amberbg)}
  .node.sink rect,.node.vuln rect{stroke:var(--red);fill:var(--redbg)}
  .node text{fill:var(--ink);font-family:var(--mono);font-size:12px}
  .node .sub{fill:var(--mut);font-size:10.5px}
  .node.plain text{fill:var(--mut)}
  .node{cursor:pointer}
  .node.sel rect{stroke-width:2.4}
  .card{width:100%;height:100%;border:1.5px solid #9a9a9a;border-radius:4px;background:#fff;overflow:hidden;display:flex;flex-direction:column;font-family:var(--mono)}
  .card.source{border-color:var(--green)}
  .card.prop{border-color:#c99a00}
  .card.sink{border-color:var(--red)}
  .card.sel{box-shadow:0 0 0 2px var(--blue)}
  .card .ch{display:flex;justify-content:space-between;gap:8px;align-items:baseline;padding:5px 9px;border-bottom:1px solid var(--rule);background:var(--panel);font-size:12px}
  .card.sink .ch{background:var(--redbg);color:var(--red)}
  .card.source .ch{background:var(--greenbg);color:var(--green)}
  .card.prop .ch{background:#fff6df;color:#7a5300}
  .card .ch .nm{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .card .ch .ad{color:var(--mut);font-weight:400;white-space:nowrap}
  .card pre.cc{margin:0;flex:1;overflow:hidden;padding:6px 9px;font-size:11px;line-height:1.45;white-space:pre}
  .card .na{color:var(--mut)}
  .edge{fill:none;stroke:#b3b3b3;stroke-width:1.3}
  .edge.taint,.edge.vuln{stroke:var(--red);stroke-width:1.8}
  .elabel{fill:var(--mut);font-size:10.5px;font-family:var(--mono)}
  mark.mk-sink{background:var(--redbg);color:var(--red);font-weight:700}
  mark.mk-src{background:var(--greenbg);color:var(--green);font-weight:700}
  mark.mk-reg{background:var(--bluebg);color:var(--blue);font-weight:700}
  mark.mk-flow{background:#fff1b8;color:#7a5300;font-weight:700;box-shadow:inset 0 -2px 0 #e0a800}
  .card .tok-com{color:#6a737d;font-style:italic}
  .card .tok-str{color:#032f62}
  .card .tok-num{color:#005cc5}
  .card .tok-kw{color:#d73a49}
  .card .tok-type{color:#6f42c1}
  .card .tok-reg{color:#e36209}
  .card .tok-mn{color:#22863a;font-weight:600}
  .card .tok-id{color:#24292e}
  .stagebox{position:absolute;right:10px;top:6px;max-width:46%;max-height:82%;overflow:auto;background:#fff;
    border:1px solid var(--rule);border-radius:2px;padding:9px 12px;font-family:var(--mono);font-size:11.5px;display:none}
  .stagebox.show{display:block}
  .stagebox h3{margin:0 0 5px;font-size:12px;font-family:var(--sans)}
  .stagebox div{color:var(--mut);padding:1px 0}
</style></head>
<body>
<header><h1>VexHound</h1><span class="meta" id="hmeta"></span></header>
<div class="stages" id="stages"></div>
<div class="wrap">
  <div class="side"><h2>Findings</h2><div id="flist"></div></div>
  <div class="main">
    <div class="toolbar">
      <button id="btnFind" class="on">Findings</button>
      <button id="btnApp">Whole application graph</button>
      <span class="nvwrap" id="nvwrap"><span class="nvlab">code in nodes:</span>
        <button class="nvbtn" data-v="ir">VEX IR</button>
        <button class="nvbtn" data-v="ghidra" id="nvGhidra">Ghidra pseudo-code</button>
        <button class="nvbtn" data-v="asm">Capstone ASM</button>
      </span>
      <span class="legend" id="legend"></span>
    </div>
    <div class="graphwrap">
      <div class="hint" id="hint"></div>
      <div class="chains" id="chains"></div>
      <svg id="svg"><g id="viewport"></g></svg>
      <div class="stagebox" id="stagebox"></div>
    </div>
  </div>
</div>
<script id="model" type="application/json">"__MODEL__"</script>
<script>
const M = JSON.parse(document.getElementById('model').textContent);
const SVGNS = "http://www.w3.org/2000/svg";
let nodeView = M.has_ghidra ? "ghidra" : "asm";
let curHL=null, curFinding=0, appMode=false;

const mit=M.mitigations||{};
const mitStr=["canary","nx","pie"].map(k=>k+" "+(mit[k]===true?"✓":mit[k]===false?"✗":"?")).join("  ·  ")
  +"  ·  relro "+(mit.relro||"?");
document.getElementById('hmeta').textContent=M.binary+"   ·   "+M.arch+"   ·   "+mitStr;
if(!M.has_ghidra){ const gb=document.getElementById('nvGhidra'); if(gb) gb.style.display='none'; }

const stagesEl=document.getElementById('stages');
M.stages.forEach(s=>{ const d=document.createElement('div'); d.className='stage';
  d.innerHTML="<b>"+esc(s.name)+"</b><span>"+esc(s.stat)+"</span>";
  d.onclick=()=>showStage(s,d); stagesEl.appendChild(d); });
function showStage(s,el){ document.querySelectorAll('.stage').forEach(x=>x.classList.remove('active')); el.classList.add('active');
  const box=document.getElementById('stagebox'); box.classList.add('show');
  box.innerHTML="<h3>"+esc(s.name)+" · "+esc(s.stat)+"</h3>"+
    (s.items.length?s.items.map(i=>"<div>"+esc(i)+"</div>").join(""):"<div>(nothing)</div>"); }

const flist=document.getElementById('flist');
M.findings.forEach((f,idx)=>{ const d=document.createElement('div'); d.className='f'; d.dataset.i=idx;
  d.innerHTML="<div class='t'>"+esc(f.sink)+"@"+esc(f.site)+"</div>"+
    "<div class='v'><span class='badge b-"+esc(f.severity)+"'>"+esc(f.severity)+"</span>"+
    "<span class='badge b-"+esc(f.verdict)+"'>"+esc(f.verdict)+"</span> "+esc(f.function)+"</div>";
  d.onclick=()=>{ selectFinding(idx); }; flist.appendChild(d); });

const vp=document.getElementById('viewport');

function layoutChain(g){
  // size every card to the CURRENT view's code (adaptive), then stack the chain:
  // sources across the top, then the propagation/sink column straight down.
  const CW=680,GAPX=44,GAPY=58,PAD=30,HEAD=34,LH=16,VP=14;
  const nlines=n=>{ const t=(M.code[n.addr]||{})[nodeView]; return t!=null?t.split("\n").length:2; };
  const nh=n=>HEAD+Math.max(2,Math.min(nlines(n),400))*LH+VP;
  const srcs=g.nodes.filter(n=>n.kind==='source'), col=g.nodes.filter(n=>n.kind!=='source');
  let maxSrcH=0;
  srcs.forEach((n,i)=>{ n.w=CW; n.h=nh(n); n.x=PAD+i*(CW+GAPX); n.y=PAD; if(n.h>maxSrcH)maxSrcH=n.h; });
  let y=PAD+(srcs.length?maxSrcH+GAPY:0);
  col.forEach(n=>{ n.w=CW; n.h=nh(n); n.x=PAD; n.y=y; y+=n.h+GAPY; });
  g.w=Math.max(PAD+Math.max(1,srcs.length)*(CW+GAPX),PAD+CW+PAD); g.h=y+PAD;
}
function drawGraph(g,opts){
  opts=opts||{}; if(opts.cards) layoutChain(g);
  vp.innerHTML=""; const byId={}; g.nodes.forEach(n=>byId[n.id]=n);
  g.edges.forEach(e=>{ const a=byId[e.from],b=byId[e.to]; if(!a||!b)return;
    let x1,y1,x2,y2,d,lx,ly;
    if(opts.vertical){ x1=a.x+a.w/2; y1=a.y+a.h; x2=b.x+b.w/2; y2=b.y; const my=(y1+y2)/2;
      d="M"+x1+","+y1+" C"+x1+","+my+" "+x2+","+my+" "+x2+","+y2; lx=(x1+x2)/2+7; ly=my; }
    else { x1=a.x+a.w; y1=a.y+a.h/2; x2=b.x; y2=b.y+b.h/2; const mx=(x1+x2)/2;
      d="M"+x1+","+y1+" C"+mx+","+y1+" "+mx+","+y2+" "+x2+","+y2; lx=mx; ly=(y1+y2)/2-4; }
    const p=document.createElementNS(SVGNS,'path'); p.setAttribute('d',d);
    p.setAttribute('class','edge '+(e.kind||'')); p.setAttribute('marker-end','url(#arw)'); vp.appendChild(p);
    if(e.label){ const t=document.createElementNS(SVGNS,'text'); t.setAttribute('x',lx); t.setAttribute('y',ly);
      t.setAttribute('class','elabel'); t.setAttribute('text-anchor','middle'); t.textContent=e.label; vp.appendChild(t); } });
  g.nodes.forEach(n=>{ vp.appendChild(opts.cards?nodeCard(n):nodeBox(n,opts.small)); });
  ensureMarker(); fit(g.w,g.h);
}

function nodeCard(n){
  const fo=document.createElementNS(SVGNS,'foreignObject');
  fo.setAttribute('x',n.x); fo.setAttribute('y',n.y); fo.setAttribute('width',n.w); fo.setAttribute('height',n.h);
  const div=document.createElement('div'); div.className='card '+n.kind; div.dataset.addr=n.addr||"";
  const code=M.code[n.addr]||{}; let body;
  if(n.addr && code[nodeView]!=null){ body=hl2(code[nodeView],nodeView,curHL); }
  else if(n.addr && nodeView==='ghidra'){ body="<span class='na'>(Ghidra pseudo-code not available; re-run with --ghidra-home)</span>"; }
  else { body=esc(n.sub||'(no code)'); }
  div.innerHTML="<div class='ch'><span class='nm'>"+esc(n.label)+"</span><span class='ad'>"+esc(n.sub||"")+"</span></div>"+
    "<pre class='cc'>"+body+"</pre>";
  div.onclick=()=>{ document.querySelectorAll('.card').forEach(c=>c.classList.remove('sel')); div.classList.add('sel'); };
  fo.appendChild(div); return fo;
}

function nodeBox(n,small){
  const grp=document.createElementNS(SVGNS,'g'); grp.setAttribute('class','node '+n.kind); grp.dataset.addr=n.addr||"";
  const r=document.createElementNS(SVGNS,'rect'); r.setAttribute('x',n.x); r.setAttribute('y',n.y);
  r.setAttribute('rx',3); r.setAttribute('width',n.w); r.setAttribute('height',n.h); grp.appendChild(r);
  const t=document.createElementNS(SVGNS,'text'); t.setAttribute('x',n.x+8); t.setAttribute('y',n.y+(small?15:20));
  if(small) t.setAttribute('font-size','11'); t.textContent=clip(n.label,small?16:24); grp.appendChild(t);
  if(n.sub && !small){ const s=document.createElementNS(SVGNS,'text'); s.setAttribute('x',n.x+8); s.setAttribute('y',n.y+35);
    s.setAttribute('class','sub'); s.textContent=clip(n.sub,30); grp.appendChild(s); }
  grp.onclick=()=>{ if(n.kind==='vuln'){ const fi=M.findings.findIndex(f=>f.function===n.label);
      if(fi>=0){ selectFinding(fi); return; } }
    document.querySelectorAll('.node').forEach(x=>x.classList.remove('sel')); grp.classList.add('sel'); };
  return grp;
}

function selectFinding(i){ curFinding=i; appMode=false; setMode();
  document.querySelectorAll('.f').forEach(x=>x.classList.remove('active'));
  const el=document.querySelector('.f[data-i="'+i+'"]'); if(el)el.classList.add('active');
  const f=M.findings[i]; curHL=f.highlight; showChains(f); drawGraph(f.graph,{cards:true,vertical:true});
}
function showChains(f){ const c=document.getElementById('chains');
  const alt=f.paths_alt||[];
  const multiHop=(f.path||"").indexOf("->")>=0;
  // Only surface the caption when it adds information: a multi-hop primary chain,
  // or an alternative handler that also reaches this sink. For a lone single-hop
  // finding it would only repeat the sidebar and cover the top card, so hide it.
  if(appMode || (!multiHop && !alt.length)){ c.style.display='none'; return; }
  let h="";
  if(f.path) h+="<b>reached via</b> <code>"+esc(f.path)+"</code>";
  if(alt.length)
    h+="<br><b>also reachable from</b> "+alt.map(p=>"<code class='alt'>"+esc(p)+"</code>").join(" &nbsp;·&nbsp; ");
  c.innerHTML=h; c.style.display='block';
}
function drawApp(){ appMode=true; setMode(); curHL=null;
  document.getElementById('chains').style.display='none';
  drawGraph(M.appgraph,{cards:false,small:true}); }

function ensureMarker(){ let defs=vp.querySelector('defs'); if(!defs){ defs=document.createElementNS(SVGNS,'defs');
  defs.innerHTML='<marker id="arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#b3b3b3"/></marker>';
  vp.appendChild(defs); } }

function setMode(){
  document.getElementById('btnFind').classList.toggle('on',!appMode);
  document.getElementById('btnApp').classList.toggle('on',appMode);
  document.getElementById('nvwrap').style.display = appMode ? 'none' : 'flex';
  document.getElementById('hint').textContent = appMode
    ? "whole call graph · red = vulnerable branch · drag / scroll to explore · click a red node to open its finding"
    : "Each card = one step where the tainted value appears, top (source) → bottom (sink). Amber = the tainted value being tracked. Switch IR / Ghidra / ASM above · scroll down the chain · drag to pan, scroll to zoom.";
  document.getElementById('legend').innerHTML = appMode
    ? "<i style='background:var(--redbg);border-color:var(--red)'></i>vulnerable<i style='background:var(--amberbg);border-color:var(--amber)'></i>on path<i style='background:#fff'></i>other"
    : "<i style='background:var(--greenbg);border-color:var(--green)'></i>source<i style='background:#fff1b8;border-color:#e0a800'></i>tainted data<i style='background:var(--bluebg);border-color:var(--blue)'></i>arg reg<i style='background:var(--redbg);border-color:var(--red)'></i>sink";
}
document.getElementById('btnFind').onclick=()=>{ selectFinding(curFinding); };
document.getElementById('btnApp').onclick=()=>{ drawApp(); };

function setNodeView(v){ nodeView=v;
  document.querySelectorAll('.nvbtn').forEach(b=>b.classList.toggle('on',b.dataset.v===v));
  if(!appMode) selectFinding(curFinding); }
document.querySelectorAll('.nvbtn').forEach(b=>b.onclick=()=>setNodeView(b.dataset.v));

// syntax highlighting: one tokenizer, coloured per view, with the taint marks
// overlaid inside each token so code colour and data-flow highlight coexist.
const IR_KW=new Set("IRSB IMark NEXT PUT GET PUTI GETI LDle LDbe STle STbe CAS Exit".split(" "));
const C_KW=new Set("if else for while do return goto switch case break continue sizeof".split(" "));
const C_TY=new Set(("void char int uint short long ulong ushort bool byte double float code "
  +"undefined undefined1 undefined2 undefined3 undefined4 undefined5 undefined6 undefined7 "
  +"undefined8 unsigned signed size_t").split(" "));
function synClass(id,view,first){
  if(view==='asm') return first?'tok-mn':'tok-id';
  if(view==='ir'){ if(/^t\d+$/.test(id))return 'tok-reg';
    if(/^(Ity|Ijk)_/.test(id))return 'tok-type'; return IR_KW.has(id)?'tok-kw':'tok-id'; }
  return C_KW.has(id)?'tok-kw':(C_TY.has(id)?'tok-type':'tok-id');
}
function taintTok(t,hl){ let s=esc(t); if(!hl) return s;
  (hl.flow||[]).forEach(v=>{ if(v) s=s.replace(rx(v),'<mark class="mk-flow">$&</mark>'); });
  (hl.sources||[]).forEach(v=>{ if(v) s=s.replace(rx(v),'<mark class="mk-src">$&</mark>'); });
  if(hl.sink) s=s.replace(rx(hl.sink),'<mark class="mk-sink">$&</mark>');
  if(hl.reg) s=s.replace(new RegExp("(?:\\$|\\b)"+esr(hl.reg)+"\\b","g"),'<mark class="mk-reg">$&</mark>');
  return s; }
function hl2(text,view,hl){
  const re=/(\/\/[^\n]*)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(0x[0-9a-fA-F]+|\b\d+\b)|(\$[A-Za-z0-9_]+)|([A-Za-z_]\w*)|(\s+)|([^\s])/g;
  let out="",m,first=true;
  while((m=re.exec(text))){
    if(m[1]) out+="<span class='tok-com'>"+esc(m[1])+"</span>";
    else if(m[2]) out+="<span class='tok-str'>"+esc(m[2])+"</span>";
    else if(m[3]) out+="<span class='tok-num'>"+esc(m[3])+"</span>";
    else if(m[4]) out+="<span class='tok-reg'>"+taintTok(m[4],hl)+"</span>";
    else if(m[5]){ const c=synClass(m[5],view,first); first=false;
      out+="<span class='"+c+"'>"+taintTok(m[5],hl)+"</span>"; }
    else if(m[6]){ out+=esc(m[6]); if(m[6].indexOf('\n')>=0) first=true; }
    else out+=esc(m[7]);
  }
  return out; }
function rx(t){ return new RegExp("(?<![A-Za-z0-9])"+esr(t)+"(?![A-Za-z0-9])","g"); }
function esr(s){ return s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'); }

let tx=0,ty=0,sc=1,drag=false,px=0,py=0; const svg=document.getElementById('svg');
function apply(){ vp.setAttribute('transform',"translate("+tx+","+ty+") scale("+sc+")"); }
function fit(w,h){ const r=svg.getBoundingClientRect();
  if(appMode){                                   // whole-app graph: fit everything in view
    sc=Math.min(1,(r.width-24)/Math.max(w,1),(r.height-24)/Math.max(h,1)); sc=Math.max(sc,0.12);
    tx=14; ty=14;
  } else {                                        // finding chain: keep code readable, fit WIDTH,
    sc=Math.min(1,(r.width-28)/Math.max(w,1));    // then scroll down the chain vertically
    sc=Math.max(sc,0.5); tx=Math.max(14,(r.width-w*sc)/2);
    const ch=document.getElementById('chains');   // start below the reachability caption
    ty=(ch && ch.style.display!=='none') ? 26+ch.offsetHeight+10 : 16;
  }
  apply(); }
svg.addEventListener('mousedown',e=>{ drag=true;px=e.clientX;py=e.clientY;svg.classList.add('drag'); });
window.addEventListener('mouseup',()=>{drag=false;svg.classList.remove('drag');});
window.addEventListener('mousemove',e=>{ if(!drag)return; tx+=e.clientX-px; ty+=e.clientY-py; px=e.clientX; py=e.clientY; apply(); });
svg.addEventListener('wheel',e=>{
  e.preventDefault(); const f=e.deltaY<0?1.1:0.9; const r=svg.getBoundingClientRect();
  const mx=e.clientX-r.left,my=e.clientY-r.top; tx=mx-(mx-tx)*f; ty=my-(my-ty)*f; sc*=f; apply(); },{passive:false});

function clip(s,n){ s=s||""; return s.length>n?s.slice(0,n-1)+"…":s; }
function esc(s){ return (s==null?"":String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

setNodeView(nodeView);
if(location.hash==='#app'){ appMode=true; }
setMode();
if(appMode){ drawApp(); }
else if(M.findings.length){ selectFinding(0); }
else { document.getElementById('hint').textContent="No findings."; }
</script>
</body></html>
"""
