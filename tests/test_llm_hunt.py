"""The LLM harness: the mechanical verifier and the VERIFIED-only gate must work
offline, with no network and no `anthropic` package. The LLM itself is mocked; only
the deterministic propose->verify->label plumbing is exercised here.

The full static pipeline is built once (module-scoped `ctx`) and shared, so the
suite pays the angr load only a single time."""
import json

import pytest
from conftest import fixture


@pytest.fixture(scope="module")
def ctx():
    pytest.importorskip("angr")
    from vexhound import llm_hunt
    return llm_hunt.HuntContext(fixture("firm_sink_mipsel"))


def test_verify_router_overflow_prover(ctx):
    # The verifier router labels an overflow by the prover's geometry: the unbounded
    # strcpy is VERIFIED, the bounded snprintf is REFUTED - deterministically, no
    # symbolic execution and no LLM.
    from vexhound import llm_hunt
    v = llm_hunt.verify_claim(ctx, {"bug_class": "overflow", "function": "soapcgi_main",
                                    "site_addr": "0x4009fc", "tainted_arg": "arg1"})
    assert v["label"] == "VERIFIED" and v["verifier"] == "prover"

    r = llm_hunt.verify_claim(ctx, {"bug_class": "overflow", "function": "hnap_main",
                                    "site_addr": "0x400a6c", "tainted_arg": "arg3"})
    assert r["label"] == "REFUTED" and r["verifier"] == "prover"


def test_triage_surfaces_verified_only(ctx):
    from vexhound import llm_hunt
    results = llm_hunt.triage(ctx, llm_hunt.MockBackend())

    assert any(x["label"] == "VERIFIED" and x["sink"] == "strcpy" for x in results)
    assert any(x["label"] == "REFUTED" and x["sink"] == "snprintf" for x in results)

    surfaced = llm_hunt.surface(results)
    assert surfaced and all(x["label"] == "VERIFIED" for x in surfaced)        # the gate
    assert any(x["sink"] == "strcpy" for x in surfaced)
    assert not any(x["sink"] == "snprintf" for x in surfaced)                   # refuted hidden


def test_discovery_verifies_injected_claim(ctx):
    # A discovery claim the model "proposes" is only surfaced after a mechanical
    # verifier confirms it. Inject a claim for the known strcpy overflow.
    from vexhound import llm_hunt
    claim = {"is_vulnerability": True, "bug_class": "overflow", "function": "soapcgi_main",
             "site_addr": "0x4009fc", "tainted_arg": "arg1",
             "rationale": "unbounded copy into a stack buffer", "suggested_verifier": "prover"}
    results = llm_hunt.discovery(ctx, llm_hunt.MockBackend(claims=[claim]), limit=1)
    assert any(x["label"] == "VERIFIED" and x["cls"] == "overflow" and x["site"] == "0x4009fc"
               for x in results)


def test_bundle_is_grounded(ctx):
    b = ctx.bundle({"function": "soapcgi_main", "addr": "0x4009fc", "cls": "overflow",
                    "sink": "strcpy", "tainted_arg": "arg1"})
    assert b["function"] == "soapcgi_main" and b["site"] == "0x4009fc"
    assert b["prover_facts"] and b["prover_facts"]["verdict"] == "OVERFLOW"
    assert "ir" in b and "asm" in b                        # code views wired in


def test_offline_backend_degrades():
    # Forcing the anthropic backend with no package/key must degrade to MockBackend,
    # never crash or make a network call. No pipeline needed.
    from vexhound import llm_hunt
    assert isinstance(llm_hunt._make_backend(backend="anthropic", agent=False),
                      llm_hunt.MockBackend)


def test_claude_code_backend_parses(monkeypatch):
    # The Claude Code backend shells out to `claude -p --output-format json
    # --json-schema ...`; verify it parses the structured_output field into claims,
    # with the subprocess mocked (no real `claude` call, no network).
    import shutil
    import subprocess
    if shutil.which("claude") is None:
        pytest.skip("claude CLI not on PATH")
    from vexhound import llm_hunt

    payload = {"structured_output": {"claims": [
        {"is_vulnerability": True, "bug_class": "overflow", "function": "f",
         "site_addr": "0x1", "rationale": "r", "suggested_verifier": "prover"}]}}

    class _Proc:
        returncode = 0
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc())
    be = llm_hunt.ClaudeCodeBackend()
    claims = be.hypothesize({"function": "f"})
    assert claims and claims[0]["bug_class"] == "overflow"
