"""
Dynamic framework library: downloads and parses CISO Assistant Community YAML files.

Supports two modes:
  - Curated catalog (FRAMEWORK_CATALOG): 12 well-known frameworks with stable IDs
  - Full discovery: fetches complete listing from GitHub API (~150+ frameworks)
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx
import yaml

from log_config import get_logger

log = get_logger(__name__)

BASE_URL = "https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/library/libraries/"
GITHUB_API_TREE = "https://api.github.com/repos/intuitem/ciso-assistant-community/git/trees/main?recursive=1"
LIBRARIES_PATH_PREFIX = "backend/library/libraries/"

# Catalog: internal ID → upstream YAML filename
FRAMEWORK_CATALOG: dict[str, str] = {
    "soc2-2017":          "soc2-2017.yaml",
    "soc2-2017-rev2022":  "soc2_2017_with_rev_2022.yaml",
    "nist-csf-1.1":       "nist-csf-1.1.yaml",
    "nist-csf-2.0":       "nist-csf-2.0.yaml",
    "nist-sp-800-53-rev5":"nist-sp-800-53-rev5.yaml",
    "nist-sp-800-66-rev2":"nist-sp-800-66-rev2.yaml",
    "iso27001-2022":      "iso27001-2022.yaml",
    "gdpr":               "gdpr.yaml",
    "pci-dss-4.0":        "pcidss-4_0.yaml",
    "nis2":               "nis2-directive.yaml",
    "dora":               "dora.yaml",
    "cmmc-2.0":           "cmmc-2.0.yaml",
}


@dataclass(frozen=True)
class FrameworkControl:
    framework_id: str
    ref_id: str
    name: Optional[str]
    description: Optional[str]
    depth: int
    assessable: bool
    parent_ref_id: Optional[str]
    urn: str


@dataclass(frozen=True)
class FrameworkMeta:
    id: str
    ref_id: str
    name: str
    description: str
    provider: str
    version: Optional[str]
    total_controls: int
    source_url: str


def _extract_ref_from_urn(urn: Optional[str]) -> Optional[str]:
    """Last segment of a URN becomes the ref_id: urn:...:cc6.1 → CC6.1."""
    if not urn:
        return None
    return urn.rsplit(":", 1)[-1].upper()


def _str_or_none(val: object) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _parse_yaml(
    framework_id: str, raw: str
) -> tuple[FrameworkMeta, list[FrameworkControl]]:
    data = yaml.safe_load(raw)

    fw_obj = data.get("objects", {}).get("framework", {})
    nodes_raw: list[dict] = fw_obj.get("requirement_nodes", [])

    controls: list[FrameworkControl] = []
    for node in nodes_raw:
        name = _str_or_none(node.get("name"))
        desc = _str_or_none(node.get("description"))

        # Fall back to French translation when English fields are empty
        if not name or not desc:
            translations = node.get("translations") or {}
            fr = translations.get("fr") or {}
            if not name:
                name = _str_or_none(fr.get("name"))
            if not desc:
                desc = _str_or_none(fr.get("description"))

        controls.append(
            FrameworkControl(
                framework_id=framework_id,
                ref_id=str(node.get("ref_id", "")).upper(),
                name=name,
                description=desc,
                depth=int(node.get("depth", 1)),
                assessable=bool(node.get("assessable", False)),
                parent_ref_id=_extract_ref_from_urn(node.get("parent_urn")),
                urn=str(node.get("urn", "")),
            )
        )

    total_controls = sum(1 for c in controls if c.assessable)

    meta = FrameworkMeta(
        id=framework_id,
        ref_id=str(data.get("ref_id", framework_id)),
        name=str(data.get("name", framework_id)),
        description=str(data.get("description", "")),
        provider=str(data.get("provider", "unknown")),
        version=_str_or_none(data.get("version")),
        total_controls=total_controls,
        source_url=BASE_URL + FRAMEWORK_CATALOG.get(framework_id, ""),
    )

    return meta, controls


class FrameworkLibrary:
    def __init__(self) -> None:
        self.data_dir = Path(__file__).parent / "data" / "frameworks"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._loaded: dict[str, tuple[FrameworkMeta, list[FrameworkControl]]] = {}
        self._meta_cache: dict[str, dict] = {}      # filename → quick_meta (in-memory)
        self._meta_cache_lock = threading.Lock()
        self._meta_cache_file = self.data_dir / ".meta_cache.json"
        # Per-framework locks prevent concurrent downloads of the same file
        self._locks: dict[str, threading.Lock] = {
            fid: threading.Lock() for fid in FRAMEWORK_CATALOG
        }
        self._load_meta_cache_from_disk()

    def load(self, framework_id: str) -> tuple[FrameworkMeta, list[FrameworkControl]]:
        if framework_id not in FRAMEWORK_CATALOG:
            raise ValueError(f"Unknown framework: {framework_id!r}. Available: {list(FRAMEWORK_CATALOG)}")

        if framework_id in self._loaded:
            return self._loaded[framework_id]

        with self._locks[framework_id]:
            # Double-checked after acquiring lock
            if framework_id in self._loaded:
                return self._loaded[framework_id]

            cached_path = self.data_dir / f"{framework_id}.yaml"
            if cached_path.exists():
                raw = cached_path.read_text(encoding="utf-8")
                log.info("framework_library: loaded %s from disk cache", framework_id)
            else:
                raw = self._download(framework_id, cached_path)

            result = _parse_yaml(framework_id, raw)
            self._loaded[framework_id] = result
            log.info(
                "framework_library: parsed %s — %d controls (%d assessable)",
                framework_id, len(result[1]), result[0].total_controls,
            )
            return result

    def _download(self, framework_id: str, dest: Path) -> str:
        url = BASE_URL + FRAMEWORK_CATALOG[framework_id]
        log.info("framework_library: downloading %s from %s", framework_id, url)
        try:
            resp = httpx.get(url, timeout=30, follow_redirects=True)
            resp.raise_for_status()
            raw = resp.text
            dest.write_text(raw, encoding="utf-8")
            log.info("framework_library: saved %s to %s", framework_id, dest)
            return raw
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Failed to download framework {framework_id!r}: {exc}") from exc

    def get_controls(
        self, framework_id: str, assessable_only: bool = True
    ) -> list[FrameworkControl]:
        _, controls = self.load(framework_id)
        if assessable_only:
            return [c for c in controls if c.assessable]
        return list(controls)

    def get_meta(self, framework_id: str) -> Optional[FrameworkMeta]:
        try:
            meta, _ = self.load(framework_id)
            return meta
        except Exception:
            return None

    def list_available(self) -> list[str]:
        return list(FRAMEWORK_CATALOG.keys())

    def list_cached(self) -> list[str]:
        return [
            fid for fid in FRAMEWORK_CATALOG
            if (self.data_dir / f"{fid}.yaml").exists()
        ]

    def search_controls(
        self, framework_id: str, query: str, assessable_only: bool = True
    ) -> list[FrameworkControl]:
        q = query.strip().lower()
        if not q:
            return []
        controls = self.get_controls(framework_id, assessable_only=assessable_only)
        return [
            c for c in controls
            if q in c.ref_id.lower()
            or (c.name and q in c.name.lower())
            or (c.description and q in c.description.lower())
        ]

    def download_all(self) -> dict[str, bool]:
        """Download all frameworks in the curated FRAMEWORK_CATALOG."""
        results: dict[str, bool] = {}
        for fid in FRAMEWORK_CATALOG:
            try:
                self.load(fid)
                results[fid] = True
            except Exception as exc:
                log.warning("framework_library: failed to load %s: %s", fid, exc)
                results[fid] = False
        return results

    def discover_from_github(self) -> list[str]:
        """Fetch complete list of YAML filenames from CISO Assistant GitHub repo.

        Returns list of filenames (e.g. 'gdpr.yaml', 'nist-csf-2.0.yaml').
        Results are cached to data/frameworks/.discovered so we don't re-fetch on restart.
        """
        cache_file = self.data_dir / ".discovered"
        if cache_file.exists():
            filenames = [
                line.strip() for line in cache_file.read_text().splitlines()
                if line.strip().endswith(".yaml")
            ]
            if filenames:
                log.info("framework_library: loaded %d filenames from discovery cache", len(filenames))
                return filenames

        log.info("framework_library: fetching file listing from GitHub API...")
        try:
            resp = httpx.get(GITHUB_API_TREE, timeout=30, follow_redirects=True)
            resp.raise_for_status()
            tree = resp.json().get("tree", [])
        except httpx.HTTPError as exc:
            raise RuntimeError(f"GitHub API fetch failed: {exc}") from exc

        filenames = [
            entry["path"].removeprefix(LIBRARIES_PATH_PREFIX)
            for entry in tree
            if entry["path"].startswith(LIBRARIES_PATH_PREFIX)
            and entry["path"].endswith(".yaml")
            and "/" not in entry["path"].removeprefix(LIBRARIES_PATH_PREFIX)
        ]

        cache_file.write_text("\n".join(filenames))
        log.info("framework_library: discovered %d YAML files", len(filenames))
        return filenames

    def _filename_to_id(self, filename: str) -> str:
        """Convert YAML filename to a stable framework ID."""
        return filename.removesuffix(".yaml").replace(" ", "_")

    def download_discovered(self, skip_existing: bool = True) -> dict[str, bool]:
        """Download ALL frameworks discovered from GitHub (~150+).

        Args:
            skip_existing: if True, skip files already present in data_dir.

        Returns dict of {framework_id: success}.
        """
        filenames = self.discover_from_github()
        results: dict[str, bool] = {}

        for filename in filenames:
            fid = self._filename_to_id(filename)
            dest = self.data_dir / filename  # store under original filename

            if skip_existing and dest.exists():
                results[fid] = True
                log.debug("framework_library: skip existing %s", filename)
                continue

            url = BASE_URL + filename
            try:
                resp = httpx.get(url, timeout=30, follow_redirects=True)
                resp.raise_for_status()
                dest.write_text(resp.text, encoding="utf-8")
                results[fid] = True
                log.info("framework_library: ✓ %s", filename)
            except Exception as exc:
                log.warning("framework_library: ✗ %s — %s", filename, exc)
                results[fid] = False

        return results

    def list_discovered(self) -> list[str]:
        """Return all YAML filenames stored in data_dir (including non-catalog ones)."""
        return [p.name for p in sorted(self.data_dir.glob("*.yaml"))]

    # ── Metadata cache helpers ────────────────────────────────────────────────

    def _load_meta_cache_from_disk(self) -> None:
        """Load persisted metadata cache from disk into memory (called once on init)."""
        if self._meta_cache_file.exists():
            try:
                self._meta_cache = json.loads(
                    self._meta_cache_file.read_text(encoding="utf-8")
                )
                log.info("framework_library: loaded meta cache (%d entries)", len(self._meta_cache))
            except Exception as exc:
                log.warning("framework_library: meta cache load failed: %s", exc)
                self._meta_cache = {}

    def _save_meta_cache_to_disk(self) -> None:
        try:
            self._meta_cache_file.write_text(
                json.dumps(self._meta_cache, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as exc:
            log.warning("framework_library: meta cache save failed: %s", exc)

    def _parse_yaml_header(self, path: Path) -> tuple[dict, int]:
        """Parse only the top-level YAML fields (before 'objects:') + count assessable controls.

        Returns (header_dict, assessable_count).
        Reading stops header collection at the 'objects:' line but continues scanning
        for 'assessable: true' occurrences — avoiding full YAML deserialization of nodes.
        """
        header_lines: list[str] = []
        assessable_count = 0
        past_objects = False
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not past_objects:
                    if line.startswith("objects:"):
                        past_objects = True
                    else:
                        header_lines.append(line)
                # Count assessable nodes by text search (avoids full YAML parse)
                if past_objects and "assessable: true" in line:
                    assessable_count += 1
        try:
            header = yaml.safe_load("".join(header_lines)) or {}
        except Exception:
            header = {}
        return header, assessable_count

    def get_quick_meta(self, filename: str) -> dict:
        """Return quick metadata for a framework file.

        Uses in-memory cache (populated from disk on init).  If the file mtime matches
        the cached entry the result is returned in O(1).  Otherwise the YAML header is
        parsed (fast: skips requirement_nodes), the result is cached and the cache file
        is updated.
        """
        path = self.data_dir / filename
        fid  = self._filename_to_id(filename)

        # Fully parsed in memory — most accurate
        if fid in self._loaded:
            meta, _ = self._loaded[fid]
            return {
                "id": fid, "filename": filename,
                "name": meta.name, "description": meta.description,
                "provider": meta.provider, "version": meta.version,
                "ref_id": meta.ref_id, "total_controls": meta.total_controls,
                "cached": True, "in_catalog": fid in FRAMEWORK_CATALOG,
                "source_url": BASE_URL + filename,
            }

        if not path.exists():
            return {"id": fid, "filename": filename, "cached": False,
                    "in_catalog": fid in FRAMEWORK_CATALOG}

        file_mtime = path.stat().st_mtime

        # Check in-memory cache (keyed by filename, validated by mtime)
        cached = self._meta_cache.get(filename)
        if cached and cached.get("_mtime") == file_mtime:
            return {k: v for k, v in cached.items() if k != "_mtime"}

        # Parse header + count assessable — fast path
        try:
            header, total_controls = self._parse_yaml_header(path)
        except Exception:
            return {"id": fid, "filename": filename, "cached": True,
                    "parse_error": True, "in_catalog": fid in FRAMEWORK_CATALOG}

        entry = {
            "id":             fid,
            "filename":       filename,
            "name":           _str_or_none(header.get("name")) or fid,
            "description":    _str_or_none(header.get("description")) or "",
            "provider":       _str_or_none(header.get("provider")) or "unknown",
            "version":        _str_or_none(header.get("version")),
            "ref_id":         _str_or_none(header.get("ref_id")) or fid,
            "total_controls": total_controls,
            "cached":         True,
            "in_catalog":     fid in FRAMEWORK_CATALOG,
            "source_url":     BASE_URL + filename,
        }
        with self._meta_cache_lock:
            self._meta_cache[filename] = {**entry, "_mtime": file_mtime}
        return entry

    def list_all_meta(self) -> list[dict]:
        """Return quick metadata for ALL downloaded frameworks (all YAMLs in data_dir).

        First call after a fresh download may take a few seconds while headers are parsed
        and the cache is written.  Subsequent calls return from the in-memory cache in ms.
        """
        filenames = self.list_discovered()
        result = [self.get_quick_meta(f) for f in filenames]
        # Persist any newly computed entries to disk
        with self._meta_cache_lock:
            self._save_meta_cache_to_disk()
        return result

    def prewarm_meta_cache(self) -> None:
        """Build the metadata cache for all discovered frameworks (intended for background startup)."""
        log.info("framework_library: prewarming metadata cache...")
        self.list_all_meta()
        log.info("framework_library: metadata cache ready (%d entries)", len(self._meta_cache))

    def load_any(self, filename: str) -> tuple[FrameworkMeta, list[FrameworkControl]]:
        """Load and parse any YAML file from data_dir by filename.

        Unlike load(), does not require the framework to be in FRAMEWORK_CATALOG.
        Uses _filename_to_id() to generate a stable ID from the filename.

        Raises:
            FileNotFoundError: if file does not exist in data_dir.
            RuntimeError: if download of a catalog framework fails.
        """
        fid  = self._filename_to_id(filename)
        path = self.data_dir / filename

        # Use catalog path if available (supports download)
        if fid in FRAMEWORK_CATALOG:
            return self.load(fid)

        # Non-catalog: read directly from disk
        if fid in self._loaded:
            return self._loaded[fid]

        if not path.exists():
            raise FileNotFoundError(f"Framework file not found: {path}")

        raw    = path.read_text(encoding="utf-8")
        result = _parse_yaml(fid, raw)
        self._loaded[fid] = result
        log.info(
            "framework_library: parsed (discovered) %s — %d controls (%d assessable)",
            filename, len(result[1]), result[0].total_controls,
        )
        return result

    def get_controls_any(self, filename: str, assessable_only: bool = True) -> list[FrameworkControl]:
        """Get controls for any downloaded framework by filename."""
        _, controls = self.load_any(filename)
        if assessable_only:
            return [c for c in controls if c.assessable]
        return list(controls)

    def search_controls_any(self, filename: str, query: str, assessable_only: bool = True) -> list[FrameworkControl]:
        """Search controls in any downloaded framework by filename."""
        q = query.strip().lower()
        if not q:
            return []
        controls = self.get_controls_any(filename, assessable_only=assessable_only)
        return [
            c for c in controls
            if q in c.ref_id.lower()
            or (c.name and q in c.name.lower())
            or (c.description and q in c.description.lower())
        ]


_library: Optional[FrameworkLibrary] = None
_library_lock = threading.Lock()


def get_library() -> FrameworkLibrary:
    global _library
    if _library is None:
        with _library_lock:
            if _library is None:
                _library = FrameworkLibrary()
    return _library
