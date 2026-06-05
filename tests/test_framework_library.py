"""Tests for framework_library.py — YAML parser and in-memory index."""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from framework_library import (
    FRAMEWORK_CATALOG,
    FrameworkControl,
    FrameworkLibrary,
    FrameworkMeta,
    _extract_ref_from_urn,
    _parse_yaml,
    get_library,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_YAML = textwrap.dedent("""\
    urn: urn:intuitem:risk:library:test-fw-1.0
    locale: en
    ref_id: TEST-FW-1.0
    name: Test Framework 1.0
    description: A test compliance framework
    version: "3"
    provider: TestOrg
    packager: test
    objects:
      framework:
        urn: urn:intuitem:risk:framework:test-fw-1.0
        ref_id: TEST-FW
        name: Test Framework
        requirement_nodes:
          - urn: urn:intuitem:risk:req_node:test-fw-1.0:cat1
            ref_id: CAT1
            name: Category One
            assessable: false
            depth: 1
            parent_urn: null
          - urn: urn:intuitem:risk:req_node:test-fw-1.0:cat1.1
            ref_id: CAT1.1
            name: Sub-category 1.1
            assessable: false
            depth: 2
            parent_urn: urn:intuitem:risk:req_node:test-fw-1.0:cat1
          - urn: urn:intuitem:risk:req_node:test-fw-1.0:cat1.1-1
            ref_id: CAT1.1-1
            name: null
            description: Ensure all assets are inventoried
            assessable: true
            depth: 3
            parent_urn: urn:intuitem:risk:req_node:test-fw-1.0:cat1.1
            translations:
              fr:
                name: Premier contrôle
                description: S'assurer que tous les actifs sont inventoriés
          - urn: urn:intuitem:risk:req_node:test-fw-1.0:cat1.1-2
            ref_id: CAT1.1-2
            name: Access control enforcement
            description: Restrict access to authorized users only
            assessable: true
            depth: 3
            parent_urn: urn:intuitem:risk:req_node:test-fw-1.0:cat1.1
""")


@pytest.fixture
def sample_parsed() -> tuple[FrameworkMeta, list[FrameworkControl]]:
    return _parse_yaml("test-fw-1.0", SAMPLE_YAML)


# ── _extract_ref_from_urn ─────────────────────────────────────────────────────

def test_extract_ref_from_urn_basic():
    assert _extract_ref_from_urn("urn:intuitem:risk:req_node:nist-csf-1.1:id.am-1") == "ID.AM-1"


def test_extract_ref_from_urn_none():
    assert _extract_ref_from_urn(None) is None


def test_extract_ref_from_urn_empty():
    assert _extract_ref_from_urn("") is None


def test_extract_ref_from_urn_single_segment():
    assert _extract_ref_from_urn("cc6.1") == "CC6.1"


# ── _parse_yaml ───────────────────────────────────────────────────────────────

def test_parse_yaml_meta(sample_parsed):
    meta, _ = sample_parsed
    assert meta.id == "test-fw-1.0"
    assert meta.ref_id == "TEST-FW-1.0"
    assert meta.name == "Test Framework 1.0"
    assert meta.provider == "TestOrg"
    assert meta.version == "3"
    assert meta.total_controls == 2  # only assessable=true nodes


def test_parse_yaml_total_nodes(sample_parsed):
    _, controls = sample_parsed
    assert len(controls) == 4  # all nodes including non-assessable


def test_parse_yaml_assessable_filter(sample_parsed):
    _, controls = sample_parsed
    assessable = [c for c in controls if c.assessable]
    assert len(assessable) == 2


def test_parse_yaml_ref_ids(sample_parsed):
    _, controls = sample_parsed
    ref_ids = {c.ref_id for c in controls}
    assert ref_ids == {"CAT1", "CAT1.1", "CAT1.1-1", "CAT1.1-2"}


def test_parse_yaml_parent_ref(sample_parsed):
    _, controls = sample_parsed
    cat1_1_1 = next(c for c in controls if c.ref_id == "CAT1.1-1")
    assert cat1_1_1.parent_ref_id == "CAT1.1"


def test_parse_yaml_depth(sample_parsed):
    _, controls = sample_parsed
    depths = {c.ref_id: c.depth for c in controls}
    assert depths["CAT1"] == 1
    assert depths["CAT1.1"] == 2
    assert depths["CAT1.1-1"] == 3


def test_parse_yaml_name_fallback_to_french(sample_parsed):
    _, controls = sample_parsed
    cat1_1_1 = next(c for c in controls if c.ref_id == "CAT1.1-1")
    # English name is null, French fallback should be used
    assert cat1_1_1.name == "Premier contrôle"


def test_parse_yaml_name_english_preferred(sample_parsed):
    _, controls = sample_parsed
    cat1_1_2 = next(c for c in controls if c.ref_id == "CAT1.1-2")
    assert cat1_1_2.name == "Access control enforcement"


def test_parse_yaml_framework_id_attached(sample_parsed):
    _, controls = sample_parsed
    assert all(c.framework_id == "test-fw-1.0" for c in controls)


def test_parse_yaml_urn_preserved(sample_parsed):
    _, controls = sample_parsed
    cat1 = next(c for c in controls if c.ref_id == "CAT1")
    assert "test-fw-1.0:cat1" in cat1.urn


# ── FrameworkLibrary ──────────────────────────────────────────────────────────

@pytest.fixture
def lib(tmp_path):
    instance = FrameworkLibrary.__new__(FrameworkLibrary)
    instance.data_dir = tmp_path / "frameworks"
    instance.data_dir.mkdir()
    instance._loaded = {}
    import threading
    instance._locks = {fid: threading.Lock() for fid in FRAMEWORK_CATALOG}
    return instance


def test_list_available_returns_all(lib):
    available = lib.list_available()
    assert len(available) == len(FRAMEWORK_CATALOG)
    assert "gdpr" in available
    assert "pci-dss-4.0" in available
    assert "nist-csf-2.0" in available


def test_list_cached_empty_initially(lib):
    assert lib.list_cached() == []


def test_list_cached_after_write(lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    assert "gdpr" in lib.list_cached()


def test_load_from_disk_cache(lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    meta, controls = lib.load("gdpr")
    assert meta.name == "Test Framework 1.0"
    assert len(controls) == 4


def test_load_caches_in_memory(lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    lib.load("gdpr")
    assert "gdpr" in lib._loaded


def test_load_unknown_framework_raises(lib):
    with pytest.raises(ValueError, match="Unknown framework"):
        lib.load("nonexistent-framework")


def test_load_triggers_download_when_missing(lib):
    mock_resp = MagicMock()
    mock_resp.text = SAMPLE_YAML
    mock_resp.raise_for_status = MagicMock()

    with patch("framework_library.httpx.get", return_value=mock_resp) as mock_get:
        meta, controls = lib.load("gdpr")

    mock_get.assert_called_once()
    call_url = mock_get.call_args[0][0]
    assert "gdpr.yaml" in call_url
    assert meta.name == "Test Framework 1.0"


def test_download_saves_to_disk(lib):
    mock_resp = MagicMock()
    mock_resp.text = SAMPLE_YAML
    mock_resp.raise_for_status = MagicMock()

    with patch("framework_library.httpx.get", return_value=mock_resp):
        lib.load("gdpr")

    assert (lib.data_dir / "gdpr.yaml").exists()


def test_get_controls_assessable_only(lib):
    (lib.data_dir / "nist-csf-1.1.yaml").write_text(SAMPLE_YAML)
    controls = lib.get_controls("nist-csf-1.1", assessable_only=True)
    assert all(c.assessable for c in controls)
    assert len(controls) == 2


def test_get_controls_all(lib):
    (lib.data_dir / "nist-csf-1.1.yaml").write_text(SAMPLE_YAML)
    controls = lib.get_controls("nist-csf-1.1", assessable_only=False)
    assert len(controls) == 4


def test_search_controls_by_ref_id(lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    results = lib.search_controls("gdpr", "CAT1.1-2")
    assert len(results) == 1
    assert results[0].ref_id == "CAT1.1-2"


def test_search_controls_by_description(lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    results = lib.search_controls("gdpr", "access control", assessable_only=False)
    assert any(c.ref_id == "CAT1.1-2" for c in results)


def test_search_controls_case_insensitive(lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    results = lib.search_controls("gdpr", "ACCESS CONTROL")
    assert len(results) >= 1


def test_search_controls_empty_query(lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    assert lib.search_controls("gdpr", "") == []


def test_get_meta_returns_none_on_download_failure(lib):
    import httpx as httpx_lib
    with patch("framework_library.httpx.get", side_effect=httpx_lib.RequestError("timeout")):
        assert lib.get_meta("gdpr") is None


def test_get_meta_after_load(lib):
    (lib.data_dir / "gdpr.yaml").write_text(SAMPLE_YAML)
    meta = lib.get_meta("gdpr")
    assert meta is not None
    assert meta.id == "gdpr"


def test_download_all_calls_load_for_each(lib):
    mock_resp = MagicMock()
    mock_resp.text = SAMPLE_YAML
    mock_resp.raise_for_status = MagicMock()

    with patch("framework_library.httpx.get", return_value=mock_resp):
        results = lib.download_all()

    assert len(results) == len(FRAMEWORK_CATALOG)
    assert all(ok for ok in results.values())


def test_download_all_marks_failure(lib):
    import httpx as httpx_lib
    with patch("framework_library.httpx.get", side_effect=httpx_lib.RequestError("timeout")):
        results = lib.download_all()

    assert all(not ok for ok in results.values())


# ── get_library singleton ─────────────────────────────────────────────────────

def test_get_library_returns_same_instance():
    lib1 = get_library()
    lib2 = get_library()
    assert lib1 is lib2


def test_get_library_returns_framework_library_instance():
    assert isinstance(get_library(), FrameworkLibrary)


# ── FRAMEWORK_CATALOG completeness ───────────────────────────────────────────

def test_catalog_has_required_frameworks():
    required = {"gdpr", "pci-dss-4.0", "nist-csf-2.0", "iso27001-2022", "hipaa" if "hipaa" in FRAMEWORK_CATALOG else "nist-sp-800-66-rev2", "dora", "nis2"}
    for fid in required - {"hipaa"}:
        assert fid in FRAMEWORK_CATALOG, f"Missing framework: {fid}"


def test_catalog_has_12_entries():
    assert len(FRAMEWORK_CATALOG) == 12


def test_all_catalog_entries_have_yaml_extension():
    for fid, filename in FRAMEWORK_CATALOG.items():
        assert filename.endswith(".yaml"), f"{fid} filename should end with .yaml"
