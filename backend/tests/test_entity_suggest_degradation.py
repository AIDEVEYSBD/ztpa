"""A dead embedding server must read as UNKNOWN, never as a measured zero.

The bug this pins: `suggest_merges` called the legacy `embed()`, which answers
`[]` for BOTH "you asked for nothing" and "every embedding provider is down".
Every candidate pair therefore scored `name_similarity: 0.0` and shipped anyway,
so an outage rendered as the positive claim "these two PCI assets do not
resemble each other". Zero similarity computed from zero data is not a
measurement.

`client.EmbeddingResult` was built to carry that distinction but nothing called
it -- `embed_texts` had zero callers outside its own module. These tests assert
the wiring exists AND that the two outcomes are externally distinguishable.
"""

from __future__ import annotations

import pytest

from src.advisory import entity_suggest
from src.advisory.client import EmbeddingResult
from src.models import Asset


def _pair() -> list[Asset]:
    """Two concrete, sensitively-tagged assets with no shared IP.

    That combination is exactly what `suggest_merges` considers: a shared IP
    would already merge deterministically, so it is skipped as a candidate.
    """
    return [
        Asset(asset_key="db-prod-01", kind="concrete", ip_set=["10.30.7.7/32"],
              tags=["pci", "prod"], source_tools=["algosec"], display_name="db-prod-01"),
        Asset(asset_key="rds-prod-customers", kind="concrete", ip_set=["10.31.2.4/32"],
              tags=["pci", "prod"], source_tools=["wiz"], display_name="rds-prod-customers"),
    ]


def _only(rows: list[dict]) -> dict:
    assert rows, "the two sensitive assets should always be proposed for review"
    return rows[0]


def test_healthy_embeddings_report_a_measured_similarity(monkeypatch):
    """Baseline: when vectors come back, the score is real and marked as such."""
    monkeypatch.setattr(entity_suggest, "embed_texts",
                        lambda texts: EmbeddingResult(vectors=[[1.0, 0.0]] * len(texts),
                                                      ok=True, provider="ollama"))
    row = _only(entity_suggest.suggest_merges(_pair()))

    assert row["similarity_available"] is True
    assert row["name_similarity"] == pytest.approx(1.0)      # identical vectors
    assert row["confidence_basis"] == "similarity+tags"
    assert row["similarity_unavailable_reason"] is None


def test_dead_embedder_does_not_fabricate_a_zero_similarity(monkeypatch):
    """THE REGRESSION. An outage must not become `name_similarity: 0.0`."""
    monkeypatch.setattr(entity_suggest, "embed_texts",
                        lambda texts: EmbeddingResult(vectors=[], ok=False, provider="none",
                                                      error="connection refused"))
    row = _only(entity_suggest.suggest_merges(_pair()))

    # The specific lie: a hard zero presented as a measurement.
    assert row["name_similarity"] is None
    assert row["name_similarity"] != 0.0
    assert row["similarity_available"] is False
    assert "connection refused" in row["similarity_unavailable_reason"]
    assert row["confidence_basis"] == "tags_only"


def test_the_two_outcomes_are_externally_distinguishable(monkeypatch):
    """A caller reading the payload can tell an outage from a real low score.

    Before the fix the degraded and measured-zero payloads were byte-identical,
    which is what let a dead server render as a confident negative.
    """
    monkeypatch.setattr(entity_suggest, "embed_texts",
                        lambda texts: EmbeddingResult(vectors=[], ok=False, provider="none",
                                                      error="connection refused"))
    degraded = _only(entity_suggest.suggest_merges(_pair()))

    # A genuine measurement that happens to be ~0: orthogonal vectors.
    monkeypatch.setattr(entity_suggest, "embed_texts",
                        lambda texts: EmbeddingResult(
                            vectors=[[1.0, 0.0], [0.0, 1.0]] * (len(texts) // 2),
                            ok=True, provider="ollama"))
    measured_zero = _only(entity_suggest.suggest_merges(_pair()))

    assert measured_zero["name_similarity"] == pytest.approx(0.0)
    assert measured_zero["similarity_available"] is True
    assert degraded != measured_zero, "an outage must not look like a measured zero"
    assert degraded["similarity_available"] != measured_zero["similarity_available"]


def test_degraded_reason_text_makes_no_resemblance_claim(monkeypatch):
    """The prose must not assert a resemblance the engine never computed."""
    monkeypatch.setattr(entity_suggest, "embed_texts",
                        lambda texts: EmbeddingResult(vectors=[], ok=False, provider="none",
                                                      error="connection refused"))
    reason = _only(entity_suggest.suggest_merges(_pair()))["reason"]

    assert "resemble the same logical asset" not in reason
    assert "could NOT be computed" in reason
    assert "unknown, not as evidence the assets differ" in reason


def test_confidence_is_not_halved_by_an_absent_similarity(monkeypatch):
    """Degraded confidence rests on tag evidence, not on a fabricated 0.0 term."""
    monkeypatch.setattr(entity_suggest, "embed_texts",
                        lambda texts: EmbeddingResult(vectors=[], ok=False, provider="none",
                                                      error="down"))
    degraded = _only(entity_suggest.suggest_merges(_pair()))["confidence"]

    # The old arithmetic was 0.5*0.0 + 0.5*tag_term, i.e. exactly half the tag
    # evidence -- a penalty applied for data that was never collected.
    tag_term = min(1.0, 0.6 + 0.2 * len(["pci"]))
    assert degraded == pytest.approx(round(tag_term, 3))
    assert degraded > round(0.5 * tag_term, 3)


def test_suggest_merges_uses_the_result_carrying_api(monkeypatch):
    """`embed_texts` must actually be the call site -- it was an orphan before.

    Guards the specific defect: `EmbeddingResult` existed, was documented against
    this exact scenario, and had zero callers outside its own module.
    """
    called: list[str] = []

    def _spy(texts):
        called.append("embed_texts")
        return EmbeddingResult(vectors=[[1.0, 0.0]] * len(texts), ok=True, provider="ollama")

    monkeypatch.setattr(entity_suggest, "embed_texts", _spy)
    entity_suggest.suggest_merges(_pair())
    assert called == ["embed_texts"]
