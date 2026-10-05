"""VexHound command-line interface.

One entry point (`vexhound`) with a subcommand per pipeline stage. Each subcommand
delegates to the same module functions the standalone scripts use, so there is a
single implementation of every analysis.
"""
import argparse
import logging
import sys

from . import __version__, banner


def build_parser():
    p = argparse.ArgumentParser(
        prog="vexhound",
        description="Architecture-neutral firmware memory-safety analysis over VEX IR.",
        epilog="Run 'vexhound <command> --help' for per-command options.")
    p.add_argument("--version", action="version", version=f"vexhound {__version__}")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="do not silence angr/pyvex logging")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    h = sub.add_parser("hunt", help="prove stack overflows from IR (fast, static)")
    h.add_argument("targets", nargs="+", help="binaries to analyze")
    h.add_argument("--json", metavar="FILE", help="write findings as JSON")
    h.add_argument("--csv", metavar="FILE", help="write findings as CSV")
    h.add_argument("--overflows-only", action="store_true",
                   help="hide command-injection and format-string findings")

    s = sub.add_parser("scan", help="full static pipeline with per-class verdicts")
    s.add_argument("targets", nargs="+", help="binaries to analyze")
    s.add_argument("--json", metavar="FILE", help="write candidates as JSON")
    s.add_argument("--csv", metavar="FILE", help="write candidates as CSV")
    s.add_argument("--report", metavar="FILE",
                   help="write an interactive HTML report (sink-to-source graph)")
    s.add_argument("--confirm", action="store_true",
                   help="also run symbolic confirmation for the report's verify stage")
    s.add_argument("--ghidra-home", metavar="DIR", default=None,
                   help="Ghidra install dir for the report's pseudo-code tab "
                        "(auto-detected from GHIDRA_HOME or common install paths)")

    c = sub.add_parser("classify", help="classify functions and extract source-to-sink flows")
    c.add_argument("targets", nargs="+", help="binaries to analyze")

    cf = sub.add_parser("confirm", help="symbolically confirm candidates")
    cf.add_argument("target", help="binary to analyze")
    cf.add_argument("--func", type=lambda x: int(x, 0),
                    help="containing function address (omit for batch mode)")
    cf.add_argument("--sink", type=lambda x: int(x, 0), help="sink call address")
    cf.add_argument("--arg", type=int, help="hint: which argument index carries taint")
    cf.add_argument("--budget", type=int, default=45, help="per-target time budget (s)")

    e = sub.add_parser("emulate", help="fire a PoV payload and observe the crash")
    e.add_argument("target", help="binary to run")
    e.add_argument("--engine", choices=["qemu", "qiling"], default="qemu",
                   help="qemu-user (static/native) or qiling (needs a rootfs)")
    e.add_argument("--rootfs", help="firmware root filesystem (qiling engine)")
    e.add_argument("--env-var", default="HTTP_SOAPACTION",
                   help="environment variable that carries the payload")
    e.add_argument("--length", type=int, default=600, help="De Bruijn payload length")
    e.add_argument("--func", type=lambda x: int(x, 0),
                   help="handler address to drive to (qiling, socket daemons)")
    e.add_argument("--main", dest="main_addr", type=lambda x: int(x, 0),
                   help="main address to run startup through before the handler")

    hl = sub.add_parser("hunt-llm",
                        help="LLM proposes bugs; prover/symbolic verifies (VERIFIED-only)")
    hl.add_argument("target", help="binary to analyze")
    hl.add_argument("--mode", choices=["triage", "discovery", "variant"], default="triage",
                    help="triage existing candidates, discover missed bugs, or variant-hunt")
    hl.add_argument("--backend", choices=["auto", "claude-code", "anthropic", "mock"],
                    default="auto",
                    help="auto prefers Claude Code (`claude -p`, your plan) over the metered API")
    hl.add_argument("--agent", action="store_true",
                    help="use the agentic Tool Runner loop (API backend only)")
    hl.add_argument("--budget", type=int, default=45,
                    help="per-candidate symbolic verification budget (s)")
    hl.add_argument("--limit", type=int, default=None,
                    help="cap how many candidates/functions are examined")
    hl.add_argument("--ghidra-home", metavar="DIR", default=None,
                    help="Ghidra install dir for decompiled-C context (auto-detected)")
    hl.add_argument("--model", default="claude-opus-5-5", help="hypothesizer model id")
    hl.add_argument("--json", metavar="FILE", help="write full labeled results as JSON")
    return p


def _emulate(args):
    if args.engine == "qemu":
        from . import emulate
        return emulate.run(args.target, args.env_var, args.length)

    from . import qiling_engine as qe
    if not args.rootfs:
        print("error: --engine qiling requires --rootfs DIR", file=sys.stderr)
        return 2
    if args.func is not None:
        if args.main_addr is None:
            print("error: --func also needs --main (entry to relocate the GOT through)",
                  file=sys.stderr)
            return 2
        res = qe.run_recv(args.target, args.rootfs, args.func, args.main_addr,
                          length=args.length)
    else:
        res = qe.run_env(args.target, args.rootfs, args.env_var, args.length, trace=True)
    for k, v in res.items():
        print(f"  {k:16}: {v}")
    return 1 if res.get("result") in ("UNAVAILABLE", "STARTUP_INCOMPLETE", "STOPPED") else 0


def dispatch(args):
    # Submodules silence logging at import time, so re-lift it after importing.
    def verbose():
        if args.verbose:
            logging.disable(logging.NOTSET)

    if args.command == "hunt":
        from . import hunt
        verbose()
        return hunt.run(args.targets, args.json, args.csv, args.overflows_only)
    if args.command == "scan":
        from . import rules
        verbose()
        return rules.run(args.targets, args.json, args.csv, report=args.report,
                         run_symbolic=args.confirm, ghidra_home=args.ghidra_home)
    if args.command == "classify":
        from . import summary
        verbose()
        return summary.run(args.targets)
    if args.command == "confirm":
        from . import symbolic
        verbose()
        return symbolic.run(args.target, args.func, args.sink, args.arg, args.budget)
    if args.command == "emulate":
        verbose()
        return _emulate(args)
    if args.command == "hunt-llm":
        from . import llm_hunt
        verbose()
        return llm_hunt.run(args.target, mode=args.mode, agent=args.agent,
                            backend=args.backend, budget_s=args.budget, limit=args.limit,
                            ghidra_home=args.ghidra_home, model=args.model,
                            json_out=args.json)
    return 2


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    banner.set_enabled(not args.no_color and banner.stdout_supports_color())

    if not args.command:
        # bare invocation: show who we are, then how to drive us
        sys.stdout.write(banner.render(__version__))
        parser.print_help()
        return 0

    if not args.no_banner:
        sys.stderr.write(banner.render(__version__))

    try:
        return dispatch(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
