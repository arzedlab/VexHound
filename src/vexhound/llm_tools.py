"""
llm_tools.py - the agentic (Tool Runner) backend for the LLM bug-hunting harness.

This is the "full harness" path: instead of one structured call per candidate, the
model drives an agentic loop with a tool belt that mirrors a human researcher
(Project Naptime's four-tool idea), split into READ tools and VERIFY tools:

  READ   list_candidates, get_decompiled, get_ir, get_taint   - grounded facts only.
  VERIFY verify_overflow, verify_symbolic                      - the mechanical oracle.

The key invariant: a finding is recorded as VERIFIED only when a VERIFY tool (which
calls llm_hunt.verify_claim -> the prover / symbolic engine) returns a positive
artifact. The model cannot promote a lead by asserting it; the ground truth is the
tool result, collected out-of-band in `_found`, not parsed from the model's prose.

Requires the `anthropic` package and an API key; imported lazily. Everything the
tools expose is already produced by the earlier pipeline stages.
"""
import logging

logging.disable(logging.CRITICAL)
import json

from . import llm_hunt

AGENT_SYSTEM = (
    "You are a firmware vulnerability researcher auditing one stripped binary. Work "
    "in a loop: use list_candidates to see the ranked suspects, read decompiled C / IR "
    "/ taint with the read tools, form a precise hypothesis about a memory-safety or "
    "command-injection bug, then CALL a verify tool to have it mechanically checked. "
    "Ground every claim in code you actually read; do not trust decompiler-invented "
    "names and never invent buffers, offsets or functions. You do not decide truth - "
    "the verify tools do. Only a bug a verify tool reports VERIFIED counts. Prioritise "
    "the highest-severity candidates and manual copy loops the sink-based rules miss. "
    "When you have verified what you can within budget, stop and summarise."
)


def _make_tools(backend):
    """Build Tool Runner tools bound to this backend's HuntContext and result sink.
    Returns a list of @beta_tool-decorated callables."""
    from anthropic import beta_tool
    ctx = backend.ctx

    def list_candidates() -> str:
        """List the ranked candidate suspect sites (bug class, function, sink, site
        address, severity) that the static stages produced for this binary."""
        rows = []
        for c in ctx.candidates():
            rows.append({"cls": c.get("cls"), "function": c.get("function"),
                         "sink": c.get("sink"), "site": c.get("addr"),
                         "severity": c.get("severity"), "tainted_arg": c.get("tainted_arg"),
                         "sources": c.get("sources")})
        return json.dumps(rows[:40])

    def get_decompiled(function: str) -> str:
        """Return the Ghidra decompiled C for a function by name (or a note if Ghidra
        is unavailable).

        Args:
            function: the function name to decompile, e.g. soapcgi_main.
        """
        addr = ctx.name2addr.get(function)
        c = ctx.decompiled(addr)
        return c or "(no decompiled C available; set --ghidra-home / $GHIDRA_HOME)"

    def get_ir(site_addr: str) -> str:
        """Return the VEX IR and Capstone assembly of the basic block at a hex address.

        Args:
            site_addr: hex address of the block/call, e.g. 0x400a08.
        """
        v = ctx.code_views(site_addr)
        return json.dumps({"ir": (v.get("ir") or "")[:2000], "asm": (v.get("asm") or "")[:2000]})

    def get_taint(function: str) -> str:
        """Return the recorded source-to-sink taint flows inside a function.

        Args:
            function: the function name to inspect.
        """
        addr = ctx.name2addr.get(function)
        flows = [f for f in ctx.eng.flows if f.get("func") == addr]
        return json.dumps([{"source": f.get("source"), "sink": f.get("sink"),
                            "at": hex(f.get("at")) if isinstance(f.get("at"), int) else f.get("at"),
                            "arg": f.get("arg")} for f in flows][:40])

    def verify_overflow(function: str, site_addr: str, tainted_arg: str = "") -> str:
        """Mechanically verify a stack-overflow claim at a call site using the prover's
        frame geometry (falls back to symbolic if the prover cannot settle it). Returns
        the label (VERIFIED / REFUTED / UNVERIFIED) and the evidence.

        Args:
            function: the containing function name.
            site_addr: hex address of the dangerous call, e.g. 0x400a08.
            tainted_arg: which argument carries attacker data, e.g. arg1 (optional).
        """
        claim = {"bug_class": "overflow", "function": function, "site_addr": site_addr,
                 "tainted_arg": tainted_arg}
        res = llm_hunt.verify_claim(ctx, claim, budget_s=backend.budget_s)
        backend._record(claim, res)
        return json.dumps({"label": res["label"], "evidence": res["evidence"]})

    def verify_symbolic(function: str, site_addr: str, bug_class: str = "overflow",
                        tainted_arg: str = "") -> str:
        """Mechanically verify reachability + an attacker-controlled trigger at a sink
        via budgeted symbolic execution. Use for command injection or overflows the
        geometry prover cannot settle. Returns the label and evidence.

        Args:
            function: the containing function name.
            site_addr: hex address of the sink call.
            bug_class: one of overflow, cmdi, fmt, alloc, uaf, other.
            tainted_arg: which argument carries attacker data, e.g. arg0 (optional).
        """
        claim = {"bug_class": bug_class, "function": function, "site_addr": site_addr,
                 "tainted_arg": tainted_arg}
        res = llm_hunt.verify_claim(ctx, claim, budget_s=backend.budget_s)
        backend._record(claim, res)
        return json.dumps({"label": res["label"], "evidence": res["evidence"]})

    return [beta_tool(f) for f in (list_candidates, get_decompiled, get_ir, get_taint,
                                   verify_overflow, verify_symbolic)]


class AnthropicAgentBackend:
    """Agentic backend: the model drives a Tool Runner loop over the read/verify tools.
    Ground truth comes from the verify tools (recorded in `_found`), not the model's
    text. Lazy-imports the Anthropic SDK; needs an API key."""
    name = "anthropic-agent"

    def __init__(self, model="claude-opus-5-5", max_iters=24):
        import anthropic
        self.anthropic = anthropic
        self.client = anthropic.Anthropic()
        self.model = model
        self.max_iters = max_iters
        self.ctx = None
        self.budget_s = 45
        self._found = []
        self._seen = set()

    def _record(self, claim, res):
        key = (claim.get("function"), llm_hunt._norm_hex(claim.get("site_addr")), res["label"])
        if key in self._seen:
            return
        self._seen.add(key)
        self._found.append({"cls": claim.get("bug_class"), "function": claim.get("function"),
                            "site": llm_hunt._norm_hex(claim.get("site_addr")),
                            "tainted_arg": claim.get("tainted_arg"),
                            "label": res["label"], "verifier": res["verifier"],
                            "evidence": res["evidence"], "llm": None})

    def hunt(self, ctx, mode="discovery", budget_s=45, limit=None):
        self.ctx = ctx
        self.budget_s = budget_s
        self._found, self._seen = [], set()
        tools = _make_tools(self)
        task = {"triage": "Confirm which ranked candidates are real bugs and drop the rest.",
                "discovery": "Find memory-safety bugs the sink-based rules missed, "
                             "especially manual copy loops into fixed stack buffers.",
                "variant": "Given the top confirmed bug, find analogues elsewhere."}.get(mode, "")
        user = (f"Audit {ctx.path} ({ctx.arch}). {task} Start with list_candidates, then "
                f"read and verify. Examine at most {limit or 8} functions. Report only "
                f"what a verify tool confirmed.")
        runner = self.client.beta.messages.tool_runner(
            model=self.model, max_tokens=16000, tools=tools,
            system=[{"type": "text", "text": AGENT_SYSTEM,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}])
        for i, _message in enumerate(runner):         # bounded agentic loop
            if i + 1 >= self.max_iters:
                break
        return self._found
