import json
from dataclasses import dataclass, field

_REQUIRED_NONEMPTY = ("test_key", "resource_id", "source", "evidence_title")
_VALID_STATUSES = frozenset({"PASS", "FAIL", "ERROR", "NA"})


@dataclass
class TestOutcome:
    test_key: str
    resource_id: str
    status: str
    evidence_title: str
    evidence_content: str
    source: str
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            raise ValueError(f"TestOutcome.status must be one of {_VALID_STATUSES}, got {self.status!r}")
        for fname in _REQUIRED_NONEMPTY:
            if not getattr(self, fname):
                raise ValueError(f"TestOutcome.{fname} must not be empty")
        try:
            json.loads(self.evidence_content)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"TestOutcome.evidence_content must be valid JSON: {exc}") from exc
