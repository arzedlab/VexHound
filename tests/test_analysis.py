import platform

import pytest
from conftest import fixture

from vexhound.emulate import cyclic, cyclic_find


def test_cyclic_locates_offsets():
    pat = cyclic(0x200)
    assert len(pat) == 0x200
    for off in (0, 4, 100, 400):
        chunk = pat[off:off + 4]
        assert cyclic_find(chunk) == off


def test_cyclic_find_accepts_packed_int():
    # a 4-byte little-endian value, as it would appear in a crashed register
    val = int.from_bytes(cyclic(0x40)[0x24:0x28], "little")
    assert cyclic_find(val, width=4) == 0x24


def test_hunt_proves_overflows_in_dir645():
    pytest.importorskip("angr")
    from vexhound.hunt import hunt
    arch, rows, _suppressed = hunt(fixture("dir645_cgibin_mipsle"))
    assert arch.startswith("MIPS")
    proven = [r for r in rows if r["method"] == "PROVEN"]
    assert proven, "expected at least one proven overflow in the DIR-645 cgibin"


def test_hedwig_sprintf_is_taint_confirmed():
    # regression guard: taint.TaintEngine.run_function used to raise on every
    # call (a leftover `from vex import ...` absolute import), which the
    # broad except in prover.py swallowed silently, so every finding fell
    # back to "tainted=False" without ever failing loudly.
    pytest.importorskip("angr")
    from vexhound.hunt import hunt
    _, rows, _ = hunt(fixture("dir645_cgibin_mipsle"))
    hedwig = [r for r in rows if r["function"] == "hedwigcgi_main" and r["sink"] == "sprintf"]
    assert hedwig, "expected the hedwig sprintf finding"
    assert any(r["tainted"] for r in hedwig), "hedwig sprintf should be taint-CONFIRMED"


def test_clean_binary_has_no_proven_overflow():
    pytest.importorskip("angr")
    from vexhound.hunt import hunt
    _, rows, _ = hunt(fixture("clean_hello_mipsel"))
    assert not [r for r in rows if r["method"] == "PROVEN"]


def test_symbolic_confirms_hedwig_with_taint():
    # the symbolic stage should reach the hedwig sprintf sink and prove the
    # argument is attacker-derived (via a claripy taint annotation, not a
    # symbolic-ness guess). Guards the libc-model + taint-propagation rewrite.
    pytest.importorskip("angr")
    from vexhound.symbolic import confirm
    r = confirm(fixture("dir645_cgibin_mipsle"), 0x40bfc0, 0x40c1a8,
                tainted_arg=0, budget_s=40)
    assert r["result"] == "CONFIRMED_SYM", r


def test_classification_finds_functions():
    pytest.importorskip("angr")
    from vexhound.summary import SummaryEngine
    eng = SummaryEngine(fixture("dir645_cgibin_mipsle"))
    eng.compute_all()
    assert eng.summaries, "expected classified functions with a body"


def test_anonymous_functions_are_analyzed_not_misattributed():
    # dlapn_main is an 8-byte tail-jump thunk; its sprintf calls really live in the
    # shared anonymous function at 0x406990 (Ghidra: FUN_00406990). Before the
    # CFG-inventory + function_blocks lower-bound fix, those calls were reported
    # under dlapn_main and the anonymous function was invisible.
    pytest.importorskip("angr")
    from vexhound.hunt import hunt
    _, rows, _ = hunt(fixture("dir645_cgibin_mipsle"))
    fns = {r["function"] for r in rows}
    assert "sub_406990" in fns, "anonymous shared function should now be analyzed"
    assert "dlapn_main" not in fns, "8-byte thunk must not absorb the shared function"


def test_reported_site_is_the_call_instruction():
    # the hedwig sprintf sink is the jalr at 0x40c1c0, not the post-call block start
    # 0x40c1a8 that angr uses as the IRSB address.
    pytest.importorskip("angr")
    from vexhound.hunt import hunt
    _, rows, _ = hunt(fixture("dir645_cgibin_mipsle"))
    hedwig = [r for r in rows if r["function"] == "hedwigcgi_main" and r["sink"] == "sprintf"]
    assert hedwig and any(r["site"] == "0x40c1c0" for r in hedwig)


def test_global_dest_not_flagged_as_stack_overflow():
    # soapcgi_main's sprintf writes into a global buffer (0x433b60), not the stack.
    # The prover must classify it NOT_STACK and the heuristic must not emit a
    # stack-buffer-overflow for it.
    pytest.importorskip("angr")
    from vexhound.hunt import hunt
    from vexhound.prover import OverflowProver
    pf = [f for f in OverflowProver(fixture("dir645_cgibin_mipsle")).run()
          if f["function"] == "soapcgi_main" and f["sink"] == "sprintf"]
    assert pf and all(f["verdict"] == "NOT_STACK" for f in pf)
    _, rows, _ = hunt(fixture("dir645_cgibin_mipsle"))
    assert not [r for r in rows if r["function"] == "soapcgi_main"
                and r["family"] == "stack-buffer-overflow"]


def test_shared_object_got_resolution():
    # PIC shared objects (ET_DYN) must resolve GOT-slot call names too, not just
    # executables. Before the load-bias fix (file offsets from the ELF's own
    # PT_LOAD vaddrs, slots rebased by the load delta) plus seeding $t9=entry for
    # the MIPS PIC gp computation, every .so returned an empty GOT and all calls
    # were anonymous, so no sinks were ever found in a shared library.
    pytest.importorskip("angr")
    from vexhound.scan import VexScan
    from vexhound.vex import normf, scan_function
    vs = VexScan(fixture("lib_mipsel_pic.so"))
    assert vs.arch.name.startswith("MIPS")
    assert vs.got, "GOT must be parsed for a shared object"
    names = {normf(v) for v in vs.got.values()}
    assert names & {"strcpy", "strlen", "memset", "printf"}, sorted(names)[:10]
    resolved = 0
    for nm, a, span in vs.functions():
        if any(n for _, n in scan_function(vs, nm, a, span)["calls"]):
            resolved += 1
        if resolved >= 3:
            break
    assert resolved >= 3, "calls should resolve through the GOT in a shared object"


def test_mitigations_detected():
    pytest.importorskip("angr")
    from vexhound.scan import elf_mitigations, mitigations_str
    m = elf_mitigations(fixture("firm_sink_x86_64"))
    assert set(m) == {"canary", "nx", "pie", "relro"}
    assert m["nx"] is True and m["pie"] is True    # modern host-compiled fixture
    assert "canary=" in mitigations_str(m)


def test_hunt_rows_carry_mitigations():
    pytest.importorskip("angr")
    from vexhound.hunt import hunt
    _, rows, _ = hunt(fixture("dir645_cgibin_mipsle"))
    assert rows and all("mitigations" in r for r in rows)


def test_pipeline_shares_one_loaded_binary():
    # regression guard for the shared-context refactor: the whole static pipeline
    # must lift the binary and build its CFG exactly once, not per stage.
    pytest.importorskip("angr")
    import vexhound.scan as scan_mod
    from vexhound.rules import RuleEngine
    orig = scan_mod.VexScan.__init__
    calls = []
    def counting(self, *a, **k):
        calls.append(1)
        return orig(self, *a, **k)
    scan_mod.VexScan.__init__ = counting
    try:
        RuleEngine(fixture("clean_hello_mipsel"))
    finally:
        scan_mod.VexScan.__init__ = orig
    assert len(calls) == 1, f"expected 1 VexScan load, got {len(calls)}"


@pytest.mark.skipif(platform.machine() not in ("x86_64", "AMD64"),
                    reason="native run needs an x86-64 host")
def test_native_emulation_crashes():
    from vexhound.emulate import fire
    r = fire(fixture("firm_sink_x86_64"), "HTTP_SOAPACTION", length=600)
    assert r["result"] == "CRASH"
