"""The evaluation harness: labels come from construction, metrics are computed
against them, and the gate fails on regressions."""

from __future__ import annotations

import json

from src.frr import evals


def test_the_labelled_set_scores_and_passes_the_gate() -> None:
    doc, labels = evals.generate(400, seed=3)
    m = evals.evaluate(doc, labels)
    assert m["micro"]["recall"] == 1.0 and m["micro"]["precision"] == 1.0
    assert {"any_any", "admin_port_exposed", "shadowed", "expired", "disabled", "unused"} <= set(m["checks"])
    assert 0 <= m["severity"]["cohens_kappa"] <= 1 and m["seconds_per_1k_rules"] > 0
    assert evals.gate(m) == []


def test_the_gate_fails_a_regression() -> None:
    doc, labels = evals.generate(200, seed=4)
    victim = next(u for u, l in labels.items() if "expired" in l["checks"])
    labels[victim]["checks"] = []                       # the engine now "finds" an unlabelled check
    uid = next(u for u, l in labels.items() if l["category"] == "clean" and l["checks"] == [])
    labels[uid]["checks"] = ["unused"]                  # ...and "misses" a labelled one
    m = evals.evaluate(doc, labels)
    fails = evals.gate(m, {**evals.GATE, "min_precision": 0.999, "min_check_recall": 0.999})
    assert any("precision" in f for f in fails) and any("unused recall" in f for f in fails)
    assert any(x["rule"] == uid for x in m["misses"])


def test_band_agreement_is_enforced_only_when_configured() -> None:
    doc, labels = evals.generate(150, seed=5)
    m = evals.evaluate(doc, labels)
    assert not any("band" in f for f in evals.gate(m))
    assert any("band" in f for f in evals.gate(m, {**evals.GATE, "min_band_agreement": 0.999}))


def test_the_cli_reads_a_real_labelled_rulebase(tmp_path, capsys) -> None:
    doc, labels = evals.generate(80, seed=6)
    (tmp_path / "e.json").write_text(json.dumps(doc))
    (tmp_path / "l.json").write_text(json.dumps(labels))
    assert evals.main(["--export", str(tmp_path / "e.json"), "--labels", str(tmp_path / "l.json"),
                       "--gate"]) == 0
    assert json.loads(capsys.readouterr().out)["rules"] == len(labels)
