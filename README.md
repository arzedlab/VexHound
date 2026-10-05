# VexHound

Architecture-neutral firmware memory-safety analysis over VEX IR.

```
 /\   /\
(  o.o  )   VexHound
 >  ^  <    firmware memory-safety analysis over VEX IR
(_______)
```

VexHound lifts firmware binaries to [VEX IR](https://github.com/angr/pyvex) with
[angr](https://angr.io) and finds memory-safety bugs by reasoning over the IR rather
than per-CPU disassembly. Because the analysis is written against the IR, one
implementation covers MIPS, ARM, PowerPC, x86 and the other architectures angr can
lift, which is what firmware analysis actually needs.

The focus is stack-buffer overflows, with supporting detection for command injection
and format strings. For overflow sites VexHound does more than pattern matching: it
recovers the destination buffer offset and the copy length from the IR, computes the
distance to the saved return address, and decides whether the write can pass it.

## Pipeline

Each stage is a module and a subcommand. Later stages consume earlier ones.

1. **classify** builds function summaries bottom-up over the call graph and labels
   each function SOURCE, SINK, PROPAGATOR or NEUTRAL from a small primitive seed,
   then extracts inter-procedural source-to-sink flows.
2. **scan** turns those flows into ranked candidates and assigns a per-class verdict
   (CONFIRMED, NEEDS_SYMBOLIC or REFUTED).
3. **hunt** is the standalone overflow oracle: the prover plus a heuristic fallback,
   reporting proven overflows, heuristic candidates and suppressed bounded copies.
4. **confirm** runs targeted symbolic execution on the survivors to prove
   intra-procedural reachability with attacker-controlled data.
5. **emulate** fires a synthesized payload (De Bruijn pattern) under qemu-user or
   Qiling and observes the crash, recovering the overflow offset.

On top of the pipeline, the optional **hunt-llm** layer lets a language model
propose additional candidates; every proposal is run through the same prover and
symbolic engine, and only mechanically verified findings are reported (see
[docs/llm-harness.md](docs/llm-harness.md)).

## Installation

Requires Python 3.9+ and the angr toolchain.

```bash
git clone https://github.com/arzedlab/vexhound
cd vexhound
python -m venv venv && . venv/bin/activate
pip install -e .
```

The Qiling emulation engine is optional and heavier:

```bash
pip install -e ".[emulation]"
```

## Usage

```
vexhound <command> [options]

  hunt      prove stack overflows from IR (fast, static)
  scan      full static pipeline with per-class verdicts
  classify  classify functions and extract source-to-sink flows
  confirm   symbolically confirm candidates
  emulate   fire a payload and observe the crash
  hunt-llm  LLM-assisted hunting with mechanical verification (optional)
```

Global flags: `--version`, `-v/--verbose`, `--no-color`, `--no-banner`.

### Examples

```bash
# Prove stack overflows in a firmware binary, overflow findings only
vexhound hunt --overflows-only path/to/httpd

# Run several binaries and export the findings
vexhound hunt bin/tddp bin/wscd bin/upnpd --json out.json --csv out.csv

# Full static pipeline with verdicts
vexhound scan path/to/httpd

# Full static pipeline, written to an interactive HTML report
vexhound scan path/to/httpd --report report.html

# Classify functions and list source-to-sink flows
vexhound classify path/to/tddp

# Symbolically confirm the NEEDS_SYMBOLIC candidates (batch)
vexhound confirm path/to/httpd

# Confirm one specific sink
vexhound confirm path/to/cgibin --func 0x4066e0 --sink 0x406a90 --budget 60

# Fire a native/qemu PoV and read the crash offset
vexhound emulate samples/corpus/firm_sink_x86_64

# Drive a socket daemon under Qiling (needs the extracted rootfs)
vexhound emulate bin/tddp --engine qiling --rootfs ./rootfs --func 0x406a90 --main 0x4011d0

# LLM-assisted triage; each proposal is mechanically verified before it is shown
vexhound hunt-llm path/to/httpd --mode triage
```

Every subcommand is also runnable on its own, sharing the same code:

```bash
python -m vexhound.hunt --overflows-only path/to/httpd
```

## Project structure

```
src/vexhound/       the package
  cli.py            argument parsing and command dispatch
  banner.py         terminal banner and color helpers
  vex.py            VEX IR block model and linear value numbering
  scan.py           IR loader (VexScan), sink pattern detection, GOT resolution
  taint.py          intra-procedural taint engine
  prover.py         per-call-site overflow prover (dest/size/room)
  hunt.py           overflow oracle: prover + heuristic merge
  summary.py        function classification and inter-procedural flows
  candidates.py     candidate composition and ranking
  rules.py          per-class static verdicts
  symbolic.py       targeted symbolic confirmation
  emulate.py        qemu-user emulation engine (De Bruijn payloads)
  qiling_engine.py  Qiling emulation engine
  llm_hunt.py       LLM hunting harness (propose, then mechanically verify)
  llm_tools.py      agentic tool-runner backend for the harness
  report.py         interactive HTML report generator
tests/              test suite and small committed fixtures
tools/              Ghidra helper scripts (optional decompilation)
docs/               concepts guide and the LLM harness design
samples/            large binaries and firmware (git-ignored, local only)
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
```

Tests use the small binaries in `tests/fixtures/`. Larger inputs live under
`samples/` (git-ignored); point the fixture locator elsewhere with
`VEXHOUND_SAMPLES=/path/to/dir`.

## License

MIT. See [LICENSE](LICENSE).
