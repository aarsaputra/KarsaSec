"""Unit tests verifying K1 Adversarial Corpus Structure & Provenance (INV-G5.4-09 & INV-G5.4-10)."""

import json
from pathlib import Path


def test_k1_corpus_manifest_partition_counts() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    assert manifest_p.exists()

    with open(manifest_p, encoding="utf-8") as f:
        data = json.load(f)

    assert data["total_cases"] == 40
    assert data["dev_count"] == 20
    assert data["val_count"] == 10
    assert data["holdout_count"] == 10

    # Verify partitions sum to total
    assert data["dev_count"] + data["val_count"] + data["holdout_count"] == 40


def test_k1_corpus_provenance_schema() -> None:
    manifest_p = Path("benchmarks/k1/manifest.json")
    with open(manifest_p, encoding="utf-8") as f:
        data = json.load(f)

    for case in data["cases"]:
        assert "case_id" in case
        assert "dataset" in case
        assert "source_artifact" in case
        assert "expected_status" in case
        assert "expected_property" in case
        assert "expected_cwe" in case
        assert "sha256" in case
        assert "partition" in case
