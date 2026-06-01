import logging
import re
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger(__name__)


def _age_days(value) -> float:
    if value is None:
        return float("inf")
    if isinstance(value, str):
        # Try fromisoformat first (handles +00:00, microseconds, Z-suffix)
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                try:
                    value = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue
            else:
                return float("inf")
    if isinstance(value, datetime):
        now = datetime.now(timezone.utc)
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return (now - value).total_seconds() / 86400.0
    return float("inf")


def _count(r: dict, p: dict) -> int:
    val = r.get(p["field"], [])
    if not isinstance(val, (list, tuple)):
        raise TypeError(f"Expected list for field '{p['field']}', got {type(val).__name__}")
    return len(val)


ASSERTERS: dict[str, Callable[[dict, dict], bool]] = {
    "field_equals":      lambda r, p: r.get(p["field"]) == p["value"],
    "field_not_equals":  lambda r, p: r.get(p["field"]) != p["value"],
    "field_in_set":      lambda r, p: r.get(p["field"]) in set(p["values"]),
    "field_not_in_set":  lambda r, p: r.get(p["field"]) not in set(p["values"]),
    "field_truthy":      lambda r, p: bool(r.get(p["field"])),
    "field_falsy":       lambda r, p: not bool(r.get(p["field"])),
    "field_exists":      lambda r, p: p["field"] in r and r[p["field"]] is not None,
    "field_missing":     lambda r, p: p["field"] not in r or r[p["field"]] is None,
    "age_less_than":     lambda r, p: _age_days(r.get(p["field"])) < p["max_days"],
    "age_greater_than":  lambda r, p: _age_days(r.get(p["field"])) > p["min_days"],
    "count_at_least":    lambda r, p: _count(r, p) >= p["min"],
    "count_at_most":     lambda r, p: _count(r, p) <= p["max"],
    "count_equals":      lambda r, p: _count(r, p) == p["value"],
    "regex_match":       lambda r, p: bool(re.search(p["pattern"], str(r.get(p["field"], "")))),
    "regex_no_match":    lambda r, p: not bool(re.search(p["pattern"], str(r.get(p["field"], "")))),
    # not_public: configurable via params.field (default "public")
    "not_public":        lambda r, p: not r.get(p.get("field", "public"), False),
    "value_gte":         lambda r, p: (r.get(p["field"]) or 0) >= p["threshold"],
    "value_lte":         lambda r, p: (r.get(p["field"]) or 0) <= p["threshold"],
    "list_contains":     lambda r, p: p["item"] in (r.get(p["field"]) or []),
    "list_not_contains": lambda r, p: p["item"] not in (r.get(p["field"]) or []),
    "string_contains":   lambda r, p: p["substring"] in str(r.get(p["field"], "")),
    "string_starts":     lambda r, p: str(r.get(p["field"], "")).startswith(p["prefix"]),
    "always_pass":       lambda r, p: True,
    "always_fail":       lambda r, p: False,
}


def run_asserter(assertion_type: str, resource: dict, params: dict) -> bool:
    fn = ASSERTERS.get(assertion_type)
    if fn is None:
        raise ValueError(f"Unknown asserter: {assertion_type}")
    try:
        return bool(fn(resource, params))
    except Exception as exc:
        log.warning(
            "Asserter '%s' raised on resource %s with params %s: %s",
            assertion_type, resource, params, exc,
        )
        return False
