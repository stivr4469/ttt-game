"""Tests for ComplianceEngine.evaluate_framework() — multi-framework evaluation path."""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from compliance_engine import (
    ComplianceEngine,
    ControlVerdict,
    VerdictStatus,
)
from framework_library import FrameworkLibrary, FRAMEWORK_CATALOG


SAMPLE_YAML = textwrap.dedent("""\
    urn: urn:intuitem:risk:library:fw-test
    locale: en
    ref_id: FW-TEST
    name: Test Framework
    description: Minimal test framework
    version: "1"
    provider: TestOrg
    packager: test
    objects:
      framework:
        urn: urn:intuitem:risk:framework:fw-test
        ref_id: FW-TEST
        name: Test Framework
        requirement_nodes:
          - urn: urn:intuitem:risk:req_node:fw-test:cat1
            ref_id: CAT1
            assessable: false
            depth: 1
          - urn: urn:intuitem:risk:req_node:fw-test:ctrl1
            ref_id: CTRL1
            name: Control One
            description: First assessable control
            assessable: true
            depth: 2
          - urn: urn:intuitem:risk:req_node:fw-test:ctrl2
            ref_id: CTRL2
            name: Control Two
            description: Second assessable control
            assessable: true
            depth: 2
          - urn: urn:intuitem:risk:req_node:fw-test:ctrl3
            ref_id: CTRL3
            name: Control Three
            description: Third assessable control
            assessable: true
            depth: 2
""")


@pytest.fixture
def lib(tmp_path):
    import threading
    instance = FrameworkLibrary.__new__(FrameworkLibrary)
    instance.data_dir = tmp_path / "frameworks"
    instance.data_dir.mkdir()
    instance._loaded = {}
    instance._locks = {fid: threading.Lock() for fid in FRAMEWORK_CATALOG}
    return instance


@pytest.fixture
def engine():
    return ComplianceEngine()


# ── evaluate_control with framework_id ───────────────────────────────────────

def test_evaluate_control_soc2_unchanged(engine):
    """SOC2 path still uses _REQUIRED_EVIDENCE_TYPES."""
    evidence = [{"status": "PASS", "evidence_type": "access_review"},
                {"status": "PASS", "evidence_type": "mfa_evidence"},
                {"status": "PASS", "evidence_type": "access_provisioning_log"}]
    verdict = engine.evaluate_control("CC6.1", evidence, framework_id="soc2")
    assert verdict.status == VerdictStatus.PASS


def test_evaluate_control_non_soc2_no_evidence_needs_review(engine):
    """Non-SOC2 control with no evidence → NEEDS_REVIEW (no required types defined)."""
    verdict = engine.evaluate_control("ID.AM-1", [], framework_id="nist-csf-2.0")
    assert verdict.status == VerdictStatus.NEEDS_REVIEW


def test_evaluate_control_non_soc2_with_pass_evidence(engine):
    """Non-SOC2 control with PASS evidence → PASS (no required types, any PASS suffices)."""
    evidence = [{"status": "PASS", "evidence_type": "asset_inventory"}]
    verdict = engine.evaluate_control("ID.AM-1", evidence, framework_id="nist-csf-2.0")
    assert verdict.status == VerdictStatus.PASS


def test_evaluate_control_non_soc2_with_fail_evidence(engine):
    """FAIL evidence always produces FAIL regardless of framework."""
    evidence = [{"status": "FAIL", "title": "Asset scan failed"}]
    verdict = engine.evaluate_control("ID.AM-1", evidence, framework_id="nist-csf-2.0")
    assert verdict.status == VerdictStatus.FAIL


def test_evaluate_control_default_framework_is_soc2(engine):
    """framework_id defaults to 'soc2' — old callers work unchanged."""
    verdict = engine.evaluate_control("CC6.1", [])
    assert verdict.status in (VerdictStatus.NEEDS_REVIEW, VerdictStatus.FAIL)


# ── evaluate_framework ────────────────────────────────────────────────────────

def test_evaluate_framework_returns_verdicts_for_all_assessable(engine, lib):
    """evaluate_framework returns one verdict per assessable control."""
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    with patch("framework_library.get_library", return_value=lib):
        verdicts = engine.evaluate_framework("gdpr", {})
    assert len(verdicts) == 3  # CTRL1, CTRL2, CTRL3


def test_evaluate_framework_empty_evidence_all_needs_review(engine, lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    with patch("framework_library.get_library", return_value=lib):
        verdicts = engine.evaluate_framework("gdpr", {})
    assert all(v.status == VerdictStatus.NEEDS_REVIEW for v in verdicts)


def test_evaluate_framework_with_pass_evidence(engine, lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    evidence_dict = {
        "CTRL1": [{"status": "PASS", "evidence_type": "doc"}],
        "CTRL2": [{"status": "PASS", "evidence_type": "doc"}],
    }
    with patch("framework_library.get_library", return_value=lib):
        verdicts = engine.evaluate_framework("gdpr", evidence_dict)
    by_id = {v.control_id: v for v in verdicts}
    assert by_id["CTRL1"].status == VerdictStatus.PASS
    assert by_id["CTRL2"].status == VerdictStatus.PASS
    assert by_id["CTRL3"].status == VerdictStatus.NEEDS_REVIEW


def test_evaluate_framework_with_fail_evidence(engine, lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    evidence_dict = {
        "CTRL1": [{"status": "FAIL", "title": "failed check"}],
    }
    with patch("framework_library.get_library", return_value=lib):
        verdicts = engine.evaluate_framework("gdpr", evidence_dict)
    by_id = {v.control_id: v for v in verdicts}
    assert by_id["CTRL1"].status == VerdictStatus.FAIL


def test_evaluate_framework_control_ids_match_ref_ids(engine, lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    with patch("framework_library.get_library", return_value=lib):
        verdicts = engine.evaluate_framework("gdpr", {})
    ref_ids = {v.control_id for v in verdicts}
    assert ref_ids == {"CTRL1", "CTRL2", "CTRL3"}


def test_evaluate_framework_unknown_raises(engine, lib):
    with patch("framework_library.get_library", return_value=lib):
        with pytest.raises(ValueError, match="Unknown framework"):
            engine.evaluate_framework("nonexistent-fw", {})


def test_evaluate_framework_mixed_results_counts(engine, lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    evidence_dict = {
        "CTRL1": [{"status": "PASS", "evidence_type": "doc"}],
        "CTRL2": [{"status": "FAIL", "title": "violation"}],
        # CTRL3: no evidence → NEEDS_REVIEW
    }
    with patch("framework_library.get_library", return_value=lib):
        verdicts = engine.evaluate_framework("gdpr", evidence_dict)
    statuses = [v.status for v in verdicts]
    assert VerdictStatus.PASS in statuses
    assert VerdictStatus.FAIL in statuses
    assert VerdictStatus.NEEDS_REVIEW in statuses


def test_evaluate_framework_returns_list(engine, lib):
    (lib.data_dir / "nist-csf-1.1.yaml").write_text(SAMPLE_YAML)
    with patch("framework_library.get_library", return_value=lib):
        result = engine.evaluate_framework("nist-csf-1.1", {})
    assert isinstance(result, list)
    assert all(isinstance(v, ControlVerdict) for v in result)


def test_evaluate_framework_empty_framework_no_controls(engine, lib):
    """YAML with zero assessable controls → empty list, no crash."""
    minimal_yaml = textwrap.dedent("""\
        urn: urn:intuitem:risk:library:empty-fw
        ref_id: EMPTY-FW
        name: Empty Framework
        description: No assessable controls
        provider: TestOrg
        objects:
          framework:
            urn: urn:intuitem:risk:framework:empty-fw
            ref_id: EMPTY-FW
            name: Empty Framework
            requirement_nodes:
              - urn: urn:intuitem:risk:req_node:empty-fw:cat1
                ref_id: CAT1
                assessable: false
                depth: 1
    """)
    (lib.data_dir / "gdpr.yaml").write_text(minimal_yaml)
    with patch("framework_library.get_library", return_value=lib):
        verdicts = engine.evaluate_framework("gdpr", {})
    assert verdicts == []
