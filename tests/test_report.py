import json
import re

import pytest
from conftest import fixture


def test_report_model_graph_and_code(tmp_path):
    # the HTML report reuses the scan pipeline and must produce, per finding, a
    # sink-to-source graph plus embedded IR/ASM for each node's address.
    pytest.importorskip("angr")
    from vexhound import report
    from vexhound.rules import RuleEngine

    path = fixture("dir645_cgibin_mipsle")
    engine = RuleEngine(path)
    model = report.build_model(engine, path)

    assert model["findings"], "expected findings"
    assert len(model["stages"]) == 9
    assert [s["id"] for s in model["stages"]] == [
        "load", "ir", "classify", "taint", "candidates", "prove", "verdict", "verify", "emulate"]
    hed = [f for f in model["findings"]
           if f["function"] == "hedwigcgi_main" and f["sink"] == "sprintf"]
    assert hed, "expected the hedwig sprintf finding"
    assert hed[0]["site"] == "0x40c1c0"          # the real call instruction, not the block
    kinds = {n["kind"] for n in hed[0]["graph"]["nodes"]}
    assert {"sink", "source"} <= kinds           # source-to-sink data-flow chain

    # each node addr resolves to real IR + assembly in the code map
    code = model["code"][hed[0]["addr"]]
    assert "IMark" in code["ir"]
    assert "jalr" in code["asm"]
    assert code["ghidra"] is None                # no ghidra-home given

    # self-contained: parseable embedded JSON, no external scripts / CDN
    out = tmp_path / "r.html"
    report.write_report(str(out), model)
    doc = out.read_text(encoding="utf-8")
    assert "0x40c1c0" in doc
    assert "<script src" not in doc.lower()
    assert "cdnjs" not in doc and "jsdelivr" not in doc
    m = re.search(r'<script id="model" type="application/json">(.*?)</script>', doc, re.DOTALL)
    assert json.loads(m.group(1))["binary"].startswith("dir645")
