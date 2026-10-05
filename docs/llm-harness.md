# The LLM bug-hunting harness (`vexhound hunt-llm`)

VexHound's static rules are sink-based, so they miss bugs that have no recognizable
libc sink: manual copy loops, vendor-specific source/sink wrappers, and multi-step
logic flaws. A language model can spot those from decompiled C, but an LLM on its
own is not a reliable detector: it will confidently report bugs that do not exist.

So the harness follows one rule:

> **The LLM proposes; a mechanical oracle disposes.** The model turns a function
> into a *checkable claim*; VexHound's prover and symbolic engine verify or refute
> it. Nothing the model merely asserts is ever reported as a bug.

VexHound is a good base for this because it already *is* the oracle (prover +
symbolic + emulate) and already produces the grounded facts (IR, CFG, taint,
decompiled C) that keep the model anchored to the real binary.

## Design principles

1. **The verifier decides truth, never the model.** The model's only job is to
   produce an artifact a verifier can check.
2. **Three tiers.** `VERIFIED` (a verifier produced a positive result) is the only
   tier shown to a human. `REFUTED` (a verifier proved it safe) is dropped.
   `UNVERIFIED` (nothing settled it within budget) is a queued lead, never a bug.
3. **Ground every claim in tool-extracted facts.** The model reasons over real IR,
   CFG, taint, and decompiler output, not free-form guesses, so it cannot invent
   buffers or offsets that are not in the binary.
4. **Use the model for localization and search direction, not whole-program
   detection.** Variant analysis (seed a known bug, find analogues) is the
   highest-yield mode.
5. **Bound cost.** Tiered models, a capped agent loop, a per-candidate symbolic
   budget, and candidate ranking as the budget allocator.

## Architecture

```
RuleEngine(path)            # single-load hub: one VexScan -> candidates + prover + taint
   -> HuntContext           # grounded facts + the verifiers (llm_hunt.HuntContext)
   -> backend proposes      # per-candidate structured call, or the agentic tool-runner loop
        a checkable claim    #   (llm_hunt.AnthropicBackend / llm_tools.AnthropicAgentBackend)
   -> verify_claim(...)     # prover geometry first, then budgeted symbolic.confirm
   -> label                 # VERIFIED / REFUTED / UNVERIFIED
   -> surface()             # VERIFIED only reaches the user
```

The verifier router (`llm_hunt.verify_claim`) sends an overflow claim to the cheap
prover geometry first (`OVERFLOW -> VERIFIED`, `SAFE/NOT_STACK -> REFUTED`);
anything the prover cannot settle, and every non-overflow claim, goes to a budgeted
`symbolic.confirm` (`CONFIRMED_SYM -> VERIFIED`, otherwise `UNVERIFIED`).

## Modes

- `triage` (default): adjudicate the existing candidate list. Static `CONFIRMED`
  findings are already VERIFIED; `REFUTED` are dropped; the `NEEDS_SYMBOLIC` middle
  is mechanically confirmed. The model only prioritizes and explains; it cannot
  promote a lead on its own. This is the cheapest, highest-return mode.
- `discovery`: ask the model for bugs the rules missed (manual copy loops first)
  over decompiled C, then verify each claim.
- `variant`: seed a known confirmed bug and ask for analogues, then verify.

The `--agent` flag swaps the per-candidate calls for an agentic tool-runner loop
(`llm_tools`), where the model drives read tools (`list_candidates`,
`get_decompiled`, `get_ir`, `get_taint`) and verify tools (`verify_overflow`,
`verify_symbolic`). The verify tools call the same `verify_claim`, so ground truth
still comes from the tool results, not the model's prose.

## Backends

`--backend` selects where the model runs; `auto` (the default) prefers the cheapest
available:

| backend | how the model is called | billing | needs |
|---|---|---|---|
| `claude-code` | shells out to `claude -p --output-format json --json-schema ...` | your Claude Code plan | the `claude` CLI, logged in |
| `anthropic` | the Anthropic SDK (`messages.create`, tool runner for `--agent`) | metered API per token | `pip install 'vexhound[llm]'` + `ANTHROPIC_API_KEY` |
| `mock` | no model; verifiers run offline | free | nothing |

`auto` picks `claude-code` when the `claude` CLI is present, then the API, then
`mock`. The agentic tool-runner loop (`--agent`) is API-only.

## Usage

```
# cheapest: run through the Claude Code CLI (no API key)
vexhound hunt-llm firmware/httpd --mode triage              # backend=auto -> claude-code
vexhound hunt-llm firmware/httpd --mode discovery --ghidra-home ~/Tools/ghidra/...

# or the metered API
pip install 'vexhound[llm]'; export ANTHROPIC_API_KEY=...
vexhound hunt-llm firmware/httpd --mode discovery --backend anthropic --agent
```

With no CLI, package, or key, the harness degrades to `mock` and still runs every
mechanical verifier offline (so `triage` still confirms the `NEEDS_SYMBOLIC` middle,
just without model proposals).

## Limits

- **Verification coverage caps the gain.** The prover is overflow-only, symbolic
  confirmation is bounded (it returns unconfirmed on deep sinks), and emulation
  needs a rootfs. Many proposals land UNVERIFIED and stay leads. The harness raises
  recall and triage quality, not soundness.
- The harness complements fuzzing and manual review; it does not replace them.
