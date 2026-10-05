"""
llm_hunt.py - an LLM bug-hunting harness that uses the
earlier stages as a GROUNDED toolbox and, crucially, as a MECHANICAL VERIFIER.

Design principle (the one every credible 2024-2026 system shares): the LLM is a
hypothesis generator; a mechanical oracle decides whether a finding is real. The
model proposes a candidate bug as a CHECKABLE CLAIM; VexHound's prover / symbolic
engine verifies or refutes it. Nothing the model merely asserts is reported as a
bug. This is what keeps the harness from becoming an "AI slop" generator.

References that shaped this (see docs/llm-harness.md):
  - Google Project Naptime/Big Sleep - "Perfect Verification": confirm memory-safety
    bugs automatically, never ask the model to judge success.
  - KLEECopilot - LLM marks candidate sites, a directed searcher verifies; ablation
    shows you need BOTH the marking and the mechanical check.
  - Veritas - ground every LLM claim in tool-extracted facts over the binary;
    distrust decompiler-invented names.
  - DARPA AIxCC - a Proof-of-Vulnerability (a triggering artifact) is the unit of
    truth; the strongest teams never reported a bug without one.

Three-tier labeling (only VERIFIED ever reaches a human):
  VERIFIED    a mechanical verifier produced a positive artifact (prover proved the
              overflow geometry, or symbolic reached the sink with an attacker-
              controlled argument).
  REFUTED     a verifier proved it is not a bug (prover showed the copy is bounded /
              not on the frame) - suppressed.
  UNVERIFIED  no verifier could settle it in budget (symbolic timed out, no model) -
              kept as a lead, never surfaced as a bug.

Modes:
  triage      adjudicate the existing candidate list; CONFIRMED static findings are
              already VERIFIED, REFUTED are dropped, and the uncertain middle
              (NEEDS_SYMBOLIC) is mechanically confirmed (optionally LLM-prioritised).
  discovery   ask the model for bugs the static rules MISSED (e.g. manual copy loops
              with no libc sink) over decompiled C, then verify each claim.
  variant     seed a known bug and ask for analogues across the binary, then verify.

The LLM path is optional: with no `anthropic` package or API key the harness falls
back to a MockBackend and still runs every mechanical verifier offline. Nothing in
this module makes a hidden network call.
"""
import logging

logging.disable(logging.CRITICAL)
import json
import os
import sys

# ---- the checkable-claim contract (structured output schemas) -----------------
_CLAIM_PROPS = {
    "is_vulnerability": {"type": "boolean"},
    "bug_class": {"type": "string",
                  "enum": ["overflow", "cmdi", "fmt", "alloc", "uaf", "other"]},
    "function": {"type": "string"},
    "site_addr": {"type": "string", "description": "hex address of the sink/op, e.g. 0x400a08"},
    "sink": {"type": "string"},
    "tainted_arg": {"type": "string", "description": "argN that carries attacker data, or empty"},
    "rationale": {"type": "string"},
    "checkable_assertion": {"type": "string",
                            "description": "the single fact a verifier must mechanically confirm"},
    "suggested_verifier": {"type": "string", "enum": ["prover", "symbolic", "emulate", "none"]},
}
CLAIM_SCHEMA = {
    "type": "object", "properties": _CLAIM_PROPS,
    "required": ["is_vulnerability", "bug_class", "function", "rationale", "suggested_verifier"],
    "additionalProperties": False,
}
CLAIMS_SCHEMA = {
    "type": "object",
    "properties": {"claims": {"type": "array", "items": CLAIM_SCHEMA}},
    "required": ["claims"], "additionalProperties": False,
}
ADJUDICATE_SCHEMA = {
    "type": "object",
    "properties": {
        "is_vulnerability": {"type": "boolean"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "rationale": {"type": "string"},
        "suggested_verifier": {"type": "string", "enum": ["prover", "symbolic", "emulate", "none"]},
    },
    "required": ["is_vulnerability", "rationale", "suggested_verifier"],
    "additionalProperties": False,
}

_GROUNDING = (
    "You are auditing a single function of a stripped firmware binary. Reason ONLY "
    "about code you can see in the provided decompiled C / IR and the tool-extracted "
    "facts. Do NOT trust decompiler-invented variable names as semantics, and never "
    "invent functions, buffers or offsets that are not shown. You do NOT decide "
    "whether a bug is real - a separate mechanical verifier does. Your job is to "
    "point precisely at a checkable claim (which sink/op, which buffer, which "
    "argument carries attacker data) so the verifier can confirm or refute it."
)
TRIAGE_SYSTEM = (
    _GROUNDING + " TASK: a static stage flagged this call as a possible bug it could "
    "not settle. Judge how plausible a real, attacker-triggerable memory-safety or "
    "command-injection bug is here, and name the verifier most likely to settle it. "
    "Prefer `prover` for stack-overflow geometry, `symbolic` for reachability/trigger."
)
DISCOVERY_SYSTEM = (
    _GROUNDING + " TASK: the sink-based static rules may have MISSED a bug in this "
    "function - especially a manual copy loop writing attacker data into a fixed-size "
    "stack buffer with no libc sink, an unchecked length, or an attacker-controlled "
    "index. Return every distinct candidate as a checkable claim with its site "
    "address. Return an empty list if nothing is defensible from what you can see."
)
VARIANT_SYSTEM = (
    _GROUNDING + " TASK: you are given a KNOWN confirmed bug (the seed) and a second "
    "function. Decide whether the second function contains the SAME CLASS of bug by "
    "the same mechanism. Return checkable claims only for genuine analogues."
)


# ---- small helpers ------------------------------------------------------------
def _norm_hex(v):
    if v is None:
        return None
    if isinstance(v, int):
        return hex(v)
    s = str(v).strip()
    try:
        return hex(int(s, 16))
    except Exception:
        return s


def _arg_index(s):
    """'arg1' / 'arg0,arg2' -> first integer index, or None."""
    if s is None:
        return None
    for tok in str(s).replace(",", " ").split():
        tok = tok.strip()
        if tok.startswith("arg") and tok[3:].isdigit():
            return int(tok[3:])
    return None


def _verdict(label, verifier, evidence, artifact=None):
    return {"label": label, "verifier": verifier, "evidence": evidence, "artifact": artifact}


def _prover_line(pf):
    dest, room, size = pf.get("dest"), pf.get("room"), pf.get("size")
    return (f"prover [{pf.get('verdict')}]: {pf.get('sink')} dest={dest} room={room} "
            f"size={size} - {pf.get('reason', '')}")


def _render_bundle(b):
    """Compact, grounded context block handed to the model."""
    out = [f"arch: {b.get('arch')}", f"function: {b.get('function')}",
           f"suspect site: {b.get('site')}   bug_class hint: {b.get('bug_class')}",
           (f"sink: {b.get('sink')}   tainted_arg: {b.get('tainted_arg')}   "
            f"sources: {b.get('sources')}"),
           f"call path: {b.get('call_path')}"]
    pf = b.get("prover_facts")
    if pf:
        out.append(f"prover facts: {pf}")
    c = b.get("decompiled_c")
    if c:
        out.append("\n--- decompiled C (Ghidra) ---\n" + c[:6000])
    ir = b.get("ir")
    if ir:
        out.append("\n--- VEX IR at the suspect site ---\n" + ir[:1500])
    return "\n".join(x for x in out if x)


# ---- the loaded context: one VexScan threaded through every stage -------------
class HuntContext:
    """Builds the whole static pipeline once (via RuleEngine's single-load hub) and
    exposes the grounded facts + the mechanical verifiers the harness needs."""

    def __init__(self, path, ghidra_home=None):
        from . import report
        from .rules import RuleEngine
        self.path = path
        self.engine = RuleEngine(path)
        self.arch = self.engine.arch
        self.pf = self.engine.pf                 # {hex(call): prover finding}
        self.eng = self.engine.cb.eng            # SummaryEngine
        self.name2addr = self.eng.name2addr
        self.proj = self.eng.vs.proj
        self._report = report
        self.ghidra_home = report.find_ghidra_home(ghidra_home)
        self._rows = None
        self._decomp = {}
        self._sym_proj = None

    def rows(self):
        if self._rows is None:
            self._rows = self.engine.run()
        return self._rows

    def candidates(self):
        return self.engine.cands

    def decompiled(self, func_addr):
        if not self.ghidra_home or func_addr is None:
            return None
        if func_addr not in self._decomp:
            try:
                d = self._report._ghidra_decompile(self.path, [func_addr], self.ghidra_home)
            except Exception:
                d = {}
            self._decomp[func_addr] = (d.get(hex(func_addr)) or {}).get("text")
        return self._decomp[func_addr]

    def code_views(self, site):
        if not site:
            return {}
        try:
            return self._report._code_for(self.proj, int(_norm_hex(site), 16))
        except Exception:
            return {}

    def sym_proj(self):
        if self._sym_proj is None:
            from . import symbolic
            self._sym_proj = symbolic.build_project(self.path)
        return self._sym_proj

    def bundle(self, item):
        """Assemble the grounded LLM context for a candidate row or a claim."""
        fn = item.get("function")
        addr = self.name2addr.get(fn)
        site = item.get("site") or item.get("addr") or item.get("site_addr")
        views = self.code_views(site)
        pf = self.pf.get(_norm_hex(site)) if site else None
        return {
            "arch": self.arch, "function": fn, "site": _norm_hex(site),
            "bug_class": item.get("cls") or item.get("bug_class"),
            "sink": item.get("sink"), "tainted_arg": item.get("tainted_arg"),
            "sources": item.get("sources"), "call_path": item.get("path"),
            "decompiled_c": self.decompiled(addr),
            "ir": views.get("ir"), "asm": views.get("asm"),
            "prover_facts": ({k: pf.get(k) for k in ("verdict", "dest", "room", "size", "reason")}
                             if pf else None),
        }


# ---- the verifier router: the only thing that may call a claim "VERIFIED" ------
def verify_claim(ctx, claim, budget_s=45):
    """Route a checkable claim to a mechanical verifier and return a labeled verdict.
    Overflow claims hit the cheap prover geometry first; anything the prover cannot
    settle (and every non-overflow claim) goes to budgeted symbolic confirmation."""
    cls = claim.get("bug_class") or claim.get("cls")
    fn = claim.get("function")
    func_addr = ctx.name2addr.get(fn)
    site = _norm_hex(claim.get("site_addr") or claim.get("site") or claim.get("addr"))
    arg = _arg_index(claim.get("tainted_arg"))

    # 1) cheap pre-filter: the prover's overflow geometry, if it has a verdict here.
    if cls == "overflow" and site:
        pf = ctx.pf.get(site)
        if pf:
            v = pf.get("verdict")
            if v == "OVERFLOW":
                return _verdict("VERIFIED", "prover", _prover_line(pf), pf)
            if v in ("SAFE", "NOT_STACK"):
                return _verdict("REFUTED", "prover", _prover_line(pf), pf)
            # CANDIDATE / UNMODELED -> fall through to symbolic

    # 2) symbolic reachability + trigger (overflow the prover could not settle, cmdi, ...)
    if func_addr is not None and site:
        from . import symbolic
        try:
            res = symbolic.confirm(ctx.path, func_addr, int(site, 16), arg,
                                   budget_s=budget_s, proj=ctx.sym_proj())
        except Exception as e:                       # a wild symbolic state is not a bug
            return _verdict("UNVERIFIED", "symbolic", f"symbolic error: {type(e).__name__}: {e}")
        if res.get("result") == "CONFIRMED_SYM":
            ev = res.get("reason", "")
            if res.get("witness"):
                ev += f"  witness={res['witness']}"
            return _verdict("VERIFIED", "symbolic", ev, res)
        return _verdict("UNVERIFIED", "symbolic", res.get("reason", "not reached in budget"), res)

    return _verdict("UNVERIFIED", "none",
                    "no mechanical verifier applies (unresolved function or site)")


# ---- backends: propose claims / adjudicate; the LLM NEVER decides truth --------
class Backend:
    name = "base"

    def adjudicate(self, bundle):
        raise NotImplementedError

    def hypothesize(self, bundle):
        raise NotImplementedError

    def find_variants(self, bundle, seed):
        raise NotImplementedError


class MockBackend(Backend):
    """Offline/test backend. With no injected data it is neutral (lets the mechanical
    verifiers run without LLM guidance); tests inject canned claims to exercise the
    full propose->verify path deterministically, with no network."""
    name = "mock"

    def __init__(self, claims=None, adjudication=None, variants=None):
        self._claims = claims
        self._adj = adjudication
        self._variants = variants

    def adjudicate(self, bundle):
        return self._adj or {"is_vulnerability": None, "confidence": "low",
                             "rationale": "(offline mock: no LLM adjudication)",
                             "suggested_verifier": "symbolic"}

    def hypothesize(self, bundle):
        return list(self._claims or [])

    def find_variants(self, bundle, seed):
        return list(self._variants or [])


class AnthropicBackend(Backend):
    """Real backend (structured single/few-shot per candidate or function). Uses the
    Anthropic SDK; imported lazily so the module loads without it. A cheap worker model
    adjudicates; the hypothesizer model proposes discovery/variant claims."""
    name = "anthropic"

    def __init__(self, model="claude-opus-5-5", worker="claude-haiku-4-5", effort="high"):
        import anthropic  # lazy: only when actually used
        self.anthropic = anthropic
        self.client = anthropic.Anthropic()
        self.model = model
        self.worker = worker
        self.effort = effort

    def _json(self, model, system, user, schema, max_tokens=4000, think=False):
        kw = {"model": model, "max_tokens": max_tokens,
              "system": [{"type": "text", "text": system,
                          "cache_control": {"type": "ephemeral"}}],
              "messages": [{"role": "user", "content": user}],
              "output_config": {"format": {"type": "json_schema", "schema": schema}}}
        if think:
            kw["thinking"] = {"type": "adaptive"}
            kw["output_config"]["effort"] = self.effort
        resp = self.client.messages.create(**kw)
        text = next((b.text for b in resp.content if b.type == "text"), "{}")
        return json.loads(text)

    def adjudicate(self, bundle):
        return self._json(self.worker, TRIAGE_SYSTEM, _render_bundle(bundle), ADJUDICATE_SCHEMA,
                          max_tokens=1500)

    def hypothesize(self, bundle):
        out = self._json(self.model, DISCOVERY_SYSTEM, _render_bundle(bundle), CLAIMS_SCHEMA,
                         max_tokens=4000, think=True)
        return out.get("claims", [])

    def find_variants(self, bundle, seed):
        user = f"SEED (known confirmed bug):\n{seed}\n\nFUNCTION TO CHECK:\n{_render_bundle(bundle)}"
        out = self._json(self.model, VARIANT_SYSTEM, user, CLAIMS_SCHEMA, max_tokens=4000, think=True)
        return out.get("claims", [])


class ClaudeCodeBackend(Backend):
    """Runs the model through the Claude Code CLI (`claude -p`) instead of the metered
    API, so calls bill against your Claude Code plan. With no ANTHROPIC_API_KEY in the
    environment, `claude -p` uses your logged-in subscription; with one set it uses the
    API. Structured output is enforced with `--json-schema`. The CLI is only required
    when this backend is actually used.

    Note: a personal subscription powering a batch pipeline consumes your plan's usage
    and is meant for your OWN use (Anthropic does not permit offering subscription login
    to third parties). Watch your usage; AnthropicBackend exists for predictable
    per-token billing."""
    name = "claude-code"

    def __init__(self, model=None, cli="claude", timeout=240):
        import shutil
        if shutil.which(cli) is None:
            raise RuntimeError(f"'{cli}' CLI not found on PATH (install Claude Code)")
        self.cli = cli
        self.model = model
        self.timeout = timeout

    def _call(self, system, user, schema):
        import subprocess
        cmd = [self.cli, "-p", user, "--output-format", "json",
               "--json-schema", json.dumps(schema), "--append-system-prompt", system]
        if self.model:
            cmd += ["--model", self.model]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout,
                              check=False)                # we inspect returncode ourselves
        if proc.returncode != 0:
            raise RuntimeError(f"claude -p failed (rc={proc.returncode}): {proc.stderr[:300]}")
        out = json.loads(proc.stdout or "{}")
        data = out.get("structured_output")
        if data is None:                                  # older CLI: parse the text result
            data = json.loads(out.get("result", "{}"))
        return data

    def adjudicate(self, bundle):
        return self._call(TRIAGE_SYSTEM, _render_bundle(bundle), ADJUDICATE_SCHEMA)

    def hypothesize(self, bundle):
        return self._call(DISCOVERY_SYSTEM, _render_bundle(bundle), CLAIMS_SCHEMA).get("claims", [])

    def find_variants(self, bundle, seed):
        user = f"SEED (known confirmed bug):\n{seed}\n\nFUNCTION TO CHECK:\n{_render_bundle(bundle)}"
        return self._call(VARIANT_SYSTEM, user, CLAIMS_SCHEMA).get("claims", [])


# ---- modes --------------------------------------------------------------------
def _row_claim(row):
    return {"bug_class": row.get("cls"), "function": row.get("function"),
            "site_addr": row.get("site") or row.get("addr"), "sink": row.get("sink"),
            "tainted_arg": row.get("tainted_arg")}


def triage(ctx, backend, budget_s=45, limit=None):
    """Adjudicate the existing candidate list. CONFIRMED static findings are already
    mechanically VERIFIED; REFUTED are dropped; the NEEDS_SYMBOLIC middle is confirmed
    by the verifier (the model only prioritises/explains - it cannot promote a lead)."""
    results = []
    rows = ctx.rows()
    if limit:
        rows = rows[:limit]
    for row in rows:
        v = row.get("verdict")
        base = {k: row.get(k) for k in ("cls", "function", "sink", "addr", "site",
                                        "severity", "score", "tainted_arg", "sources", "path")}
        if v == "CONFIRMED":
            results.append({**base, "label": "VERIFIED", "verifier": "rules/prover",
                            "evidence": row.get("evidence", ""), "llm": None})
        elif v == "REFUTED":
            results.append({**base, "label": "REFUTED", "verifier": "rules/prover",
                            "evidence": row.get("evidence", ""), "llm": None})
        else:  # NEEDS_SYMBOLIC - the uncertain middle
            try:
                adj = backend.adjudicate(ctx.bundle(row))
            except Exception as e:                       # a backend hiccup is not a bug
                adj = {"error": f"{type(e).__name__}: {e}"[:150]}
            res = verify_claim(ctx, _row_claim(row), budget_s=budget_s)
            results.append({**base, "label": res["label"], "verifier": res["verifier"],
                            "evidence": res["evidence"], "llm": adj})
    return results


def _discovery_targets(ctx, limit):
    """Functions worth asking the model about. Ranked candidates come first; then we
    broaden to functions that read attacker input or look like request handlers, so
    discovery still works on binaries where the sink-based rules flagged nothing (the
    exact case the LLM is meant to cover). Returns candidate-shaped dicts."""
    targets, seen = [], set()
    for c in ctx.candidates():
        fn = c.get("function")
        if fn and fn not in seen:
            seen.add(fn)
            targets.append(c)
    eng = ctx.eng
    cap = (limit or 8) * 3
    for addr, summ in (getattr(eng, "summaries", {}) or {}).items():
        name = eng.funcs.get(addr, ("",))[0]
        if not name or name in seen:
            continue
        low = name.lower()
        handlerish = (name.endswith(("_main", "cgi")) or "handle" in low
                      or "http" in low or "cgi" in low or "request" in low)
        if getattr(summ, "reads_input", False) or handlerish:
            seen.add(name)
            targets.append({"function": name, "addr": hex(addr), "cls": "overflow",
                            "sink": None, "tainted_arg": None, "sources": None, "path": None})
        if len(targets) >= cap:
            break
    return targets


def _hunt_claims(ctx, backend, mode, budget_s, limit, items, seed=None):
    """Shared discovery/variant driver: bundle each target function, ask the backend
    for claims, verify each. Dedupe functions so we spend budget per function."""
    results, seen_fn = [], set()
    for c in items:
        fn = c.get("function")
        if fn in seen_fn:
            continue
        seen_fn.add(fn)
        if limit and len(seen_fn) > limit:
            break
        bundle = ctx.bundle(c)
        try:
            claims = (backend.find_variants(bundle, seed) if mode == "variant"
                      else backend.hypothesize(bundle))
        except Exception as e:                           # a backend hiccup skips a function
            print(f"[llm] backend error on {fn}: {type(e).__name__}: {e}")
            claims = []
        for claim in claims:
            if not claim.get("is_vulnerability", True):
                continue
            claim.setdefault("function", fn)
            res = verify_claim(ctx, claim, budget_s=budget_s)
            results.append({"cls": claim.get("bug_class"), "function": claim.get("function"),
                            "sink": claim.get("sink"), "site": _norm_hex(claim.get("site_addr")),
                            "tainted_arg": claim.get("tainted_arg"),
                            "label": res["label"], "verifier": res["verifier"],
                            "evidence": res["evidence"],
                            "llm": {"rationale": claim.get("rationale"),
                                    "assertion": claim.get("checkable_assertion")}})
    return results


def discovery(ctx, backend, budget_s=45, limit=None):
    return _hunt_claims(ctx, backend, "discovery", budget_s, limit, _discovery_targets(ctx, limit))


def variant(ctx, backend, seed, budget_s=45, limit=None):
    return _hunt_claims(ctx, backend, "variant", budget_s, limit, ctx.candidates(), seed=seed)


def surface(results):
    """The output gate: only VERIFIED findings reach a human."""
    return [r for r in results if r["label"] == "VERIFIED"]


# ---- runner / CLI -------------------------------------------------------------
def _have_api():
    try:
        import anthropic  # noqa: F401
    except Exception:
        return False
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def _cc_model(model):
    # pass an explicit --model only when the user changed it from the default
    return None if model == "claude-opus-5-5" else model


def _make_backend(backend="auto", agent=False, model="claude-opus-5-5", worker="claude-haiku-4-5"):
    """Choose a backend. 'auto' prefers Claude Code (bills your plan, not the metered
    API), then the API, then the offline MockBackend. The agentic Tool Runner loop is
    API-only, so --agent implies the API backend."""
    import shutil
    have_cli = shutil.which("claude") is not None

    if backend == "mock":
        return MockBackend()
    if backend == "claude-code":
        try:
            return ClaudeCodeBackend(model=_cc_model(model))
        except Exception as e:
            print(f"[llm] claude-code backend unavailable ({e}) - using MockBackend")
            return MockBackend()
    if backend == "anthropic":
        if not _have_api():
            print("[llm] anthropic backend needs the package + ANTHROPIC_API_KEY - "
                  "using MockBackend")
            return MockBackend()
        if agent:
            from .llm_tools import AnthropicAgentBackend
            return AnthropicAgentBackend(model=model)
        return AnthropicBackend(model=model, worker=worker)

    # auto
    if agent and _have_api():
        from .llm_tools import AnthropicAgentBackend
        return AnthropicAgentBackend(model=model)
    if have_cli:
        print("[llm] using Claude Code (`claude -p`) - bills your Claude Code plan, not the API")
        return ClaudeCodeBackend(model=_cc_model(model))
    if _have_api():
        return AnthropicBackend(model=model, worker=worker)
    print("[llm] no Claude Code CLI and no API key - running verifiers offline with MockBackend")
    return MockBackend()


def _print_results(path, mode, results):
    from . import banner
    verified = surface(results)
    nver = len(verified)
    nlead = sum(1 for r in results if r["label"] == "UNVERIFIED")
    nref = sum(1 for r in results if r["label"] == "REFUTED")
    print(banner.rule(os.path.basename(path)) if hasattr(banner, "rule") else "=" * 70)
    print(f"  mode {mode}   {nver} verified   {nlead} unverified lead(s) queued   "
          f"{nref} refuted (suppressed)\n")
    if not verified:
        print("  no VERIFIED findings (only mechanically confirmed bugs are surfaced).")
    for r in verified:
        site = r.get("site") or r.get("addr")
        print(f"  VERIFIED  {r.get('cls'):8} {r.get('sink')}@{site}  {r.get('function')}  "
              f"[{r.get('verifier')}]")
        print(f"      {r.get('evidence', '')}")


def run(path, mode="triage", agent=False, backend="auto", budget_s=45, limit=None,
        ghidra_home=None, model="claude-opus-5-5", json_out=None):
    """Build the pipeline once, run the chosen mode, surface VERIFIED findings only."""
    ctx = HuntContext(path, ghidra_home=ghidra_home)
    backend = _make_backend(backend=backend, agent=agent, model=model)
    if agent and getattr(backend, "name", "") == "anthropic-agent":
        results = backend.hunt(ctx, mode=mode, budget_s=budget_s, limit=limit)
    elif mode == "triage":
        results = triage(ctx, backend, budget_s=budget_s, limit=limit)
    elif mode == "discovery":
        results = discovery(ctx, backend, budget_s=budget_s, limit=limit)
    elif mode == "variant":
        seed = _default_seed(ctx)
        results = variant(ctx, backend, seed, budget_s=budget_s, limit=limit)
    else:
        print(f"[llm] unknown mode {mode!r}")
        return 2
    _print_results(path, mode, results)
    if json_out:
        with open(json_out, "w") as fh:
            json.dump({"binary": path, "mode": mode, "results": results}, fh, indent=2, default=str)
        print(f"\n[+] wrote {json_out}")
    return 0


def _default_seed(ctx):
    """Use the highest-severity CONFIRMED finding as the variant-analysis seed."""
    for row in ctx.rows():
        if row.get("verdict") == "CONFIRMED":
            return (f"{row.get('cls')} via {row.get('sink')} in {row.get('function')}: "
                    f"{row.get('evidence', '')}")
    return "a stack buffer overflow: attacker data copied unbounded into a fixed stack buffer."


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="vexhound hunt-llm",
        description="LLM proposes candidate bugs; VexHound's prover/symbolic verifies them.")
    ap.add_argument("target", help="binary to analyze")
    ap.add_argument("--mode", choices=["triage", "discovery", "variant"], default="triage")
    ap.add_argument("--backend", choices=["auto", "claude-code", "anthropic", "mock"],
                    default="auto",
                    help="auto prefers Claude Code (`claude -p`, your plan) over the metered API")
    ap.add_argument("--agent", action="store_true",
                    help="use the agentic Tool Runner loop (API backend only)")
    ap.add_argument("--budget", type=int, default=45, help="per-candidate symbolic budget (s)")
    ap.add_argument("--limit", type=int, default=None, help="cap candidates/functions examined")
    ap.add_argument("--ghidra-home", default=None, help="Ghidra install for decompiled-C context")
    ap.add_argument("--model", default="claude-opus-5-5", help="hypothesizer model id")
    ap.add_argument("--json", default=None, help="write full labeled results to this path")
    a = ap.parse_args(argv)
    return run(a.target, mode=a.mode, agent=a.agent, backend=a.backend, budget_s=a.budget,
               limit=a.limit, ghidra_home=a.ghidra_home, model=a.model, json_out=a.json)


if __name__ == "__main__":
    sys.exit(main())
