"""
test_outcome.py — Standard contract for compliance agent test results.

Agents collect TestOutcome objects during their checks and can submit
them in bulk to POST /api/v1/test-results/batch.

Usage:
    from test_outcome import TestOutcome, submit_outcomes

    outcomes = [
        TestOutcome(test_key="github.repo.branch_protection", status="PASS"),
        TestOutcome(test_key="github.dependabot.enabled", status="FAIL",
                    details={"reason": "Dependabot not enabled"}),
    ]
    submit_outcomes(outcomes, api_url="http://localhost:8000",
                    api_key="...", tenant_id="acme")
"""

from dataclasses import dataclass, field
from typing import Optional


# Valid status values accepted by the batch endpoint
VALID_STATUSES = frozenset({"PASS", "FAIL", "ERROR", "NA"})


@dataclass
class TestOutcome:
    """Represents the result of a single compliance check performed by an agent.

    Attributes:
        test_key:    Matches a TestDefinition.key in the test catalog.
        status:      One of PASS | FAIL | ERROR | NA.
        resource_id: Identifies the specific resource evaluated (repo name,
                     user email, device ID, etc.). Defaults to "*" for
                     checks that cover the entire scope.
        details:     Arbitrary key-value pairs with check-specific context.
        evidence_id: Optional UUID of an Evidence record already created in
                     the Evidence Tracker, to link result → evidence.
        run_id:      Optional UUID of an existing TestRun to attach to.
                     When None, the batch endpoint creates a new run.
    """

    test_key: str
    status: str                          # PASS | FAIL | ERROR | NA
    resource_id: str = "*"
    details: dict = field(default_factory=dict)
    evidence_id: Optional[str] = None
    run_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{self.status}'. Must be one of {sorted(VALID_STATUSES)}"
            )
        if not self.test_key:
            raise ValueError("test_key must not be empty")


def submit_outcomes(
    outcomes: list[TestOutcome],
    api_url: str,
    api_key: str,
    tenant_id: Optional[str] = None,
    producer: str = "agent",
    trigger: str = "scheduled",
) -> dict:
    """Submit a list of TestOutcome objects to POST /api/v1/test-results/batch.

    Args:
        outcomes:   Test results collected by the agent.
        api_url:    Base URL of the Evidence Tracker API (e.g. "http://localhost:8000").
        api_key:    Value for the X-API-Key header.
        tenant_id:  Optional tenant identifier sent as X-Tenant-ID header.
        producer:   Label identifying the submitting agent (default "agent").
        trigger:    How the run was triggered — "scheduled" | "manual" | "webhook".

    Returns:
        Parsed JSON response from the API:
        {"run_id": "...", "inserted": N, "skipped": M, "affected_controls": K}

    Raises:
        requests.HTTPError: When the API returns a non-2xx status.
        requests.RequestException: On network-level failures.
    """
    import requests  # local import keeps module importable without requests installed

    if not outcomes:
        return {"run_id": None, "inserted": 0, "skipped": 0, "affected_controls": 0}

    headers: dict[str, str] = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    if tenant_id:
        headers["X-Tenant-ID"] = tenant_id

    # The batch endpoint groups all items under a single TestRun.
    # If every outcome carries the same run_id we forward it; otherwise
    # we let the server create a new run (run_id=None in BatchRequest).
    run_ids = {o.run_id for o in outcomes} - {None}
    batch_run_id = run_ids.pop() if len(run_ids) == 1 else None

    payload: dict = {
        "producer": producer,
        "trigger": trigger,
        "results": [
            {
                "test_key": o.test_key,
                "status": o.status,
                "resource_id": o.resource_id,
                "details": o.details,
                # evidence_id and run_id are per-item optional fields
                # currently accepted by the server but not persisted yet —
                # include them for forward-compatibility.
                **({"evidence_id": o.evidence_id} if o.evidence_id else {}),
            }
            for o in outcomes
        ],
    }
    if batch_run_id:
        payload["run_id"] = batch_run_id

    resp = requests.post(
        f"{api_url.rstrip('/')}/api/v1/test-results/batch",
        json=payload,
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()
