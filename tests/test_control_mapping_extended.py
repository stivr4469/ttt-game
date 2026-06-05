"""Tests for the extended FrameworkMapping (GDPR, HIPAA, PCI DSS v4 crosswalk)."""
from __future__ import annotations

import pytest

from control_mapping import (
    CONTROL_MAPPINGS,
    SUPPORTED_FRAMEWORKS,
    ControlMappingEngine,
    FrameworkMapping,
    _GDPR_INDEX,
    _HIPAA_INDEX,
    _PCI_INDEX,
    get_engine,
)


# ── FrameworkMapping dataclass ────────────────────────────────────────────────

def test_framework_mapping_has_gdpr_field():
    m = CONTROL_MAPPINGS[0]
    assert hasattr(m, "gdpr")
    assert isinstance(m.gdpr, tuple)


def test_framework_mapping_has_hipaa_field():
    m = CONTROL_MAPPINGS[0]
    assert hasattr(m, "hipaa")
    assert isinstance(m.hipaa, tuple)


def test_framework_mapping_has_pci_dss_v4_field():
    m = CONTROL_MAPPINGS[0]
    assert hasattr(m, "pci_dss_v4")
    assert isinstance(m.pci_dss_v4, tuple)


def test_all_controls_have_gdpr_data():
    """Every control should have at least one GDPR reference."""
    empty = [m.soc2 for m in CONTROL_MAPPINGS if not m.gdpr]
    assert not empty, f"Controls missing GDPR data: {empty}"


def test_all_controls_have_hipaa_data():
    empty = [m.soc2 for m in CONTROL_MAPPINGS if not m.hipaa]
    assert not empty, f"Controls missing HIPAA data: {empty}"


def test_all_controls_have_pci_data():
    empty = [m.soc2 for m in CONTROL_MAPPINGS if not m.pci_dss_v4]
    assert not empty, f"Controls missing PCI DSS data: {empty}"


# ── Key crosswalk spot-checks ─────────────────────────────────────────────────

def test_cc6_1_gdpr_includes_art32():
    cc6_1 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC6.1")
    assert any("Art.32" in ref for ref in cc6_1.gdpr)


def test_cc6_1_hipaa_includes_164_312():
    cc6_1 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC6.1")
    assert any("164.312" in ref for ref in cc6_1.hipaa)


def test_cc6_1_pci_includes_requirement_7():
    cc6_1 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC6.1")
    assert any(ref.startswith("7") for ref in cc6_1.pci_dss_v4)


def test_cc7_3_gdpr_includes_breach_notification():
    """CC7.3 (incident detection) must map to GDPR Art.33 (72h breach notification)."""
    cc7_3 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC7.3")
    assert "Art.33" in cc7_3.gdpr


def test_cc9_2_gdpr_includes_art28():
    """CC9.2 (vendor risk) must map to GDPR Art.28 (processor agreements)."""
    cc9_2 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC9.2")
    assert "Art.28" in cc9_2.gdpr


def test_cc6_5_gdpr_includes_right_to_erasure():
    """CC6.5 (offboarding) must map to GDPR Art.17 (right to erasure)."""
    cc6_5 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC6.5")
    assert "Art.17" in cc6_5.gdpr


def test_p1_1_gdpr_includes_transparency():
    """P1.1 (privacy notice) must map to GDPR Art.12-14."""
    p1_1 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "P1.1")
    assert "Art.12" in p1_1.gdpr


def test_cc6_8_hipaa_includes_malware():
    """CC6.8 (malware prevention) must map to HIPAA 164.308(a)(5)(ii)(B)."""
    cc6_8 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC6.8")
    assert "164.308(a)(5)(ii)(B)" in cc6_8.hipaa


def test_cc9_2_hipaa_includes_baa():
    """CC9.2 (vendor risk) must map to HIPAA 164.308(b)(1) (BAA requirement)."""
    cc9_2 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC9.2")
    assert "164.308(b)(1)" in cc9_2.hipaa


def test_cc6_7_pci_includes_encryption():
    """CC6.7 (data transfer) must map to PCI DSS 4.2 (encryption in transit)."""
    cc6_7 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC6.7")
    assert "4.2" in cc6_7.pci_dss_v4


def test_cc7_2_pci_includes_log_review():
    """CC7.2 (monitoring) must map to PCI DSS 10.4 (audit log review)."""
    cc7_2 = next(m for m in CONTROL_MAPPINGS if m.soc2 == "CC7.2")
    assert "10.4" in cc7_2.pci_dss_v4


# ── Index integrity ────────────────────────────────────────────────────────────

def test_gdpr_index_built():
    assert len(_GDPR_INDEX) > 0


def test_hipaa_index_built():
    assert len(_HIPAA_INDEX) > 0


def test_pci_index_built():
    assert len(_PCI_INDEX) > 0


def test_gdpr_index_art32_maps_to_multiple_soc2():
    """Art.32 is referenced by many controls."""
    art32_refs = [v for k, v in _GDPR_INDEX.items() if "Art.32" in k]
    all_soc2 = [soc2 for lst in art32_refs for soc2 in lst]
    assert len(all_soc2) >= 3


def test_pci_index_contains_section_8():
    """PCI section 8 (auth) should be referenced by at least CC6.1 and CC6.2."""
    sec8_refs = [v for k, v in _PCI_INDEX.items() if k.startswith("8")]
    all_soc2 = {soc2 for lst in sec8_refs for soc2 in lst}
    assert "CC6.1" in all_soc2 or "CC6.2" in all_soc2


# ── ControlMappingEngine new lookup methods ────────────────────────────────────

@pytest.fixture
def engine() -> ControlMappingEngine:
    return get_engine()


def test_engine_get_soc2_for_gdpr_art32(engine):
    results = engine.get_soc2_for_gdpr("Art.32(1)(b)")
    assert len(results) >= 1
    assert "CC6.1" in results


def test_engine_get_soc2_for_gdpr_returns_empty_for_unknown(engine):
    assert engine.get_soc2_for_gdpr("Art.99") == []


def test_engine_get_soc2_for_hipaa_164_312(engine):
    results = engine.get_soc2_for_hipaa("164.312(a)(1)")
    assert "CC6.1" in results


def test_engine_get_soc2_for_hipaa_returns_empty_for_unknown(engine):
    assert engine.get_soc2_for_hipaa("164.999") == []


def test_engine_get_soc2_for_pci_7(engine):
    results = engine.get_soc2_for_pci("7.1")
    assert "CC6.1" in results


def test_engine_get_soc2_for_pci_returns_empty_for_unknown(engine):
    assert engine.get_soc2_for_pci("99.99") == []


# ── Search extended ────────────────────────────────────────────────────────────

def test_search_finds_gdpr_reference(engine):
    results = engine.search("Art.33")
    soc2_ids = [m.soc2 for m in results]
    assert "CC7.3" in soc2_ids or "CC7.4" in soc2_ids


def test_search_finds_hipaa_reference(engine):
    results = engine.search("164.308")
    assert len(results) >= 3


def test_search_finds_pci_reference(engine):
    results = engine.search("12.10")
    soc2_ids = [m.soc2 for m in results]
    assert "CC7.3" in soc2_ids or "CC7.4" in soc2_ids


# ── Coverage report ────────────────────────────────────────────────────────────

def test_coverage_report_includes_gdpr(engine):
    report = engine.get_coverage_report()
    assert "gdpr" in report["frameworks"]


def test_coverage_report_includes_hipaa(engine):
    report = engine.get_coverage_report()
    assert "hipaa" in report["frameworks"]


def test_coverage_report_includes_pci(engine):
    report = engine.get_coverage_report()
    assert "pci_dss_v4" in report["frameworks"]


def test_coverage_report_gdpr_100_percent(engine):
    report = engine.get_coverage_report()
    assert report["frameworks"]["gdpr"]["coverage_pct"] == 100.0


def test_coverage_report_hipaa_100_percent(engine):
    report = engine.get_coverage_report()
    assert report["frameworks"]["hipaa"]["coverage_pct"] == 100.0


def test_coverage_report_pci_100_percent(engine):
    report = engine.get_coverage_report()
    assert report["frameworks"]["pci_dss_v4"]["coverage_pct"] == 100.0


# ── SUPPORTED_FRAMEWORKS ──────────────────────────────────────────────────────

def test_supported_frameworks_includes_gdpr():
    ids = {f["id"] for f in SUPPORTED_FRAMEWORKS}
    assert "gdpr" in ids


def test_supported_frameworks_includes_hipaa():
    ids = {f["id"] for f in SUPPORTED_FRAMEWORKS}
    assert "hipaa" in ids


def test_supported_frameworks_includes_pci():
    ids = {f["id"] for f in SUPPORTED_FRAMEWORKS}
    assert "pci_dss_v4" in ids


def test_supported_frameworks_count():
    assert len(SUPPORTED_FRAMEWORKS) == 7
