"""Тесты для ESignatureAgent — signature requests, simulate, pending."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import pytest
import inspect
from unittest.mock import MagicMock, patch
from esignature_agent import ESignatureAgent, SIGNATURE_REQUIRED_CONTROLS, main


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("esignature_agent.EvidenceClient"):
        return ESignatureAgent()


class TestConstants:
    def test_cc11_in_required_controls(self):
        assert "CC1.1" in SIGNATURE_REQUIRED_CONTROLS

    def test_cc15_in_required_controls(self):
        assert "CC1.5" in SIGNATURE_REQUIRED_CONTROLS

    def test_at_least_4_controls(self):
        assert len(SIGNATURE_REQUIRED_CONTROLS) >= 4

    def test_main_accepts_controls_map(self):
        sig = inspect.signature(main)
        assert "controls_map" in sig.parameters


class TestCreateSignatureRequest:
    def test_returns_envelope_id(self, agent):
        req = agent.create_signature_request("CC1.1", "Test Policy", "ciso@test.com", "CISO")
        assert "envelope_id" in req
        assert len(req["envelope_id"]) > 0

    def test_returns_signature_url(self, agent):
        req = agent.create_signature_request("CC1.1", "Test Policy", "ciso@test.com", "CISO")
        assert "signature_url" in req
        assert "envelope_id" in req["signature_url"] or req["envelope_id"][:8] in req["signature_url"]

    def test_envelope_ids_are_unique(self, agent):
        req1 = agent.create_signature_request("CC1.1", "Policy A", "a@test.com", "A")
        req2 = agent.create_signature_request("CC1.5", "Policy B", "b@test.com", "B")
        assert req1["envelope_id"] != req2["envelope_id"]

    def test_request_saved_to_file(self, agent):
        agent.create_signature_request("CC1.1", "Test Policy", "ciso@test.com", "CISO")
        data = json.load(open("policy_signatures.json"))
        assert len(data["signatures"]) == 1

    def test_saved_request_has_status_sent(self, agent):
        agent.create_signature_request("CC1.1", "Test Policy", "ciso@test.com", "CISO")
        data = json.load(open("policy_signatures.json"))
        assert data["signatures"][0]["status"] == "sent"

    def test_saved_request_has_correct_control(self, agent):
        agent.create_signature_request("CC1.5", "Accountability Policy", "ciso@test.com", "CISO")
        data = json.load(open("policy_signatures.json"))
        assert data["signatures"][0]["control_code"] == "CC1.5"

    def test_signed_at_is_null_initially(self, agent):
        agent.create_signature_request("CC1.1", "Test Policy", "ciso@test.com", "CISO")
        data = json.load(open("policy_signatures.json"))
        assert data["signatures"][0]["signed_at"] is None


class TestGetPendingSignatures:
    def test_empty_initially(self, agent):
        pending = agent.get_pending_signatures()
        assert pending == []

    def test_returns_sent_requests(self, agent):
        agent.create_signature_request("CC1.1", "Policy A", "a@test.com", "A")
        agent.create_signature_request("CC1.5", "Policy B", "b@test.com", "B")
        pending = agent.get_pending_signatures()
        assert len(pending) == 2

    def test_does_not_return_signed(self, agent):
        req = agent.create_signature_request("CC1.1", "Policy", "a@test.com", "A")
        with patch.object(agent, "process_signed_policy", return_value={}):
            agent.simulate_signature(req["envelope_id"])
        pending = agent.get_pending_signatures()
        assert len(pending) == 0


class TestSimulateSignature:
    def test_returns_error_for_unknown_envelope(self, agent):
        result = agent.simulate_signature("nonexistent-envelope-id")
        assert "error" in result

    def test_no_exception_for_unknown_envelope(self, agent):
        result = agent.simulate_signature("bad-id-12345")
        assert isinstance(result, dict)

    def test_marks_envelope_as_signed(self, agent):
        req = agent.create_signature_request("CC1.1", "Policy", "a@test.com", "A")
        with patch.object(agent, "process_signed_policy", return_value={"status": "processed"}):
            agent.simulate_signature(req["envelope_id"])
        data = json.load(open("policy_signatures.json"))
        assert data["signatures"][0]["status"] == "signed"
        assert data["signatures"][0]["signed_at"] is not None
