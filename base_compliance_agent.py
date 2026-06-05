"""Base class for all SOC 2 compliance scanner agents."""

from __future__ import annotations

import abc
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from evidence_client import EvidenceClient
from slack_notifier import SlackNotifier
from test_outcome import TestOutcome

log = logging.getLogger(__name__)


@dataclass
class AgentFinding:
    control: str
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    detail: dict = field(default_factory=dict)


@dataclass
class AgentResult:
    agent_name: str
    started_at: str
    completed_at: str
    findings: list[AgentFinding]
    outcomes: list[TestOutcome]
    control_results: dict[str, str]  # code → "PASS" | "FAIL"


class BaseComplianceAgent(abc.ABC):
    """
    Standard interface for all compliance scanner agents.

    Subclass and implement authenticate() and run_checks().
    Use _pass() / _fail() to record control results and emit evidence.
    Optionally append to self.outcomes for TestOutcome batch submission.

    Usage:
        agent = MyAgent(controls_map, evidence_url, slack_webhook)
        result = agent.run()
    """

    CONTROLS: dict[str, str] = {}  # override: { "CC6.2": "description", ... }

    def __init__(
        self,
        controls_map: dict[str, str],
        evidence_url: str,
        slack_webhook: Optional[str] = None,
    ) -> None:
        self.controls_map = controls_map
        self._ec = EvidenceClient(evidence_url, agent_name=self.agent_name)
        self._slack = SlackNotifier(slack_webhook) if slack_webhook else None
        self.findings: list[AgentFinding] = []
        self.outcomes: list[TestOutcome] = []
        self.results: dict[str, str] = {code: "PASS" for code in self.CONTROLS}

    @property
    def agent_name(self) -> str:
        """Lowercase class name used as evidence source and test key prefix."""
        return type(self).__name__.lower()

    @abc.abstractmethod
    def authenticate(self) -> None:
        """Validate credentials and initialise API clients.

        Raise ValueError or RuntimeError if required credentials are missing.
        Called once at the start of run().
        """
        ...

    @abc.abstractmethod
    def run_checks(self) -> None:
        """Execute all compliance checks.

        Call _pass() and _fail() for each control result.
        Append TestOutcome instances to self.outcomes as needed.
        """
        ...

    # ── Template method ───────────────────────────────────────────────────────

    def run(self) -> AgentResult:
        """Orchestrate the full scan lifecycle: authenticate → checks → notify."""
        started_at = datetime.now(timezone.utc).isoformat()
        self.authenticate()
        self.run_checks()
        if self._slack:
            self._notify_slack()
        return AgentResult(
            agent_name=self.agent_name,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc).isoformat(),
            findings=list(self.findings),
            outcomes=list(self.outcomes),
            control_results=dict(self.results),
        )

    # ── Result helpers ────────────────────────────────────────────────────────

    def _fail(
        self,
        code: str,
        title: str,
        content: dict,
        severity: str,
        test_key: Optional[str] = None,
    ) -> None:
        """Record a FAIL result, emit evidence, update control status."""
        ctrl_id = self.controls_map.get(code)
        if ctrl_id:
            self._ec.create_evidence(
                control_id=ctrl_id,
                title=title,
                content=json.dumps({**content, "control": code, "severity": severity}),
                source=self.agent_name.upper(),
            )
            key = test_key or f"{self.agent_name}.{code.lower().replace('.', '_')}.fail"
            self._ec.submit_test_result(ctrl_id, "FAIL", test_key=key, producer=self.agent_name)
        self.results[code] = "FAIL"
        self.findings.append(AgentFinding(control=code, title=title, severity=severity, detail=content))
        icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
        print(f"  {icon} [{code}] {title} ({severity})")

    def _pass(
        self,
        code: str,
        title: str,
        content: dict,
        test_key: Optional[str] = None,
    ) -> None:
        """Record a PASS result and emit evidence."""
        ctrl_id = self.controls_map.get(code)
        if ctrl_id:
            self._ec.create_evidence(
                control_id=ctrl_id,
                title=title,
                content=json.dumps({**content, "control": code, "status": "PASS"}),
                source=self.agent_name.upper(),
            )
            key = test_key or f"{self.agent_name}.{code.lower().replace('.', '_')}.pass"
            self._ec.submit_test_result(ctrl_id, "PASS", test_key=key, producer=self.agent_name)
        self.results[code] = "PASS"
        print(f"  ✅ [{code}] {title}")

    def _submit_test_result(
        self,
        code: str,
        status: str,
        test_key: str,
    ) -> None:
        """Submit a test result for a control without creating evidence.

        Used by agents that manage test keys independently (e.g. MDM, Vuln).
        """
        ctrl_id = self.controls_map.get(code)
        if ctrl_id:
            self._ec.submit_test_result(ctrl_id, status, test_key=test_key, producer=self.agent_name)

    # ── Slack notification ────────────────────────────────────────────────────

    def _notify_slack(self) -> None:
        if not self._slack:
            return
        total = len(self.findings)
        crit = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high = sum(1 for f in self.findings if f.severity == "HIGH")
        fail_codes = [c for c, s in self.results.items() if s == "FAIL"]
        lines = [
            f"🔍 *{type(self).__name__} scan complete*",
            f"Findings: {total} | 🔴 CRITICAL: {crit} | 🟠 HIGH: {high}",
            f"Failed controls: {', '.join(fail_codes)}" if fail_codes else "✅ All controls PASS",
        ]
        for f in self.findings[:8]:
            icon = "🔴" if f.severity == "CRITICAL" else "🟠"
            lines.append(f"  {icon} {f.title}")
        self._slack.send({"text": "\n".join(lines)})
