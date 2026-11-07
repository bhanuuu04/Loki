import json
import pytest

from loki.security.lab_verification import (
    extract_canary_records,
    validate_canary_marker,
)
from loki.security.context import AssessmentSecurityContext
from loki.security.policy_engine import ExecutionMode
from loki.security.scope_manager import ScopeConfig, ScopeManager
from loki.assessment.store import AssessmentStore
from loki.assessment.models import ConfidenceLevel
from loki.tools import security_tools


def _marker():
    return "LOKI-LAB-CANARY:" + "a" * 32


def test_canary_marker_validation():
    assert validate_canary_marker(_marker())
    assert not validate_canary_marker("LOKI-LAB-CANARY:short")
    assert not validate_canary_marker("LOKI-LAB-CANARY:" + "a" * 100)
    assert not validate_canary_marker("not-a-loki-canary")


def test_extractor_requires_exact_canary_field_and_redacts_sensitive_values():
    marker = _marker()
    body = json.dumps({
        "items": [
            {
                "id": 17,
                "loki_canary": marker,
                "record": "dummy-fixture",
                "password": "not-for-output",
                "email": "dummy@example.test",
            }
        ]
    }).encode()

    records = extract_canary_records(body, marker)
    assert len(records) == 1
    assert records[0]["id"] == 17
    assert records[0]["loki_canary"] == marker
    assert records[0]["record"] == "dummy-fixture"
    assert records[0]["password"] == "[REDACTED]"
    assert records[0]["email"] == "[REDACTED]"

    # Reflection in a generic text body or an unrelated JSON field is not proof.
    assert extract_canary_records(marker.encode(), marker) == []
    assert extract_canary_records(json.dumps({"message": marker}).encode(), marker) == []


class _FakeResponse:
    def __init__(self, body, status=200, content_type="application/json"):
        self.status_code = status
        self.headers = {"content-type": content_type}
        self._body = body

    async def aiter_bytes(self):
        yield self._body


class _FakeStream:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeClient:
    last_request = None
    response = None

    def __init__(self, **kwargs):
        self.options = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def stream(self, method, url, headers=None):
        self.__class__.last_request = {
            "method": method,
            "url": url,
            "headers": headers or {},
            "options": self.options,
        }
        return _FakeStream(self.__class__.response)


@pytest.fixture
def lab_context(tmp_path, monkeypatch):
    config = ScopeConfig(
        assessment_name="Disposable Lab",
        targets=["lab.example.test"],
        dns_check_enabled=False,
        lab_mode_enabled=True,
    )
    scope = ScopeManager(config)
    store = AssessmentStore(storage_dir=str(tmp_path / "assessments"))
    ctx = AssessmentSecurityContext(scope_manager=scope, assessment_store=store)
    ctx.policy_engine.set_mode(ExecutionMode.NOMERCY, operator_confirmed=True)
    ctx.active_assessment_id = "lab_disposable"
    store.create_assessment(ctx.active_assessment_id, "Disposable Lab", config)
    AssessmentSecurityContext.reset_default(ctx)
    monkeypatch.setattr(security_tools.httpx, "AsyncClient", _FakeClient)
    return ctx


@pytest.mark.asyncio
async def test_nomercy_lab_probe_retrieves_only_seeded_fixture_and_records_finding(lab_context):
    marker = _marker()
    _FakeClient.response = _FakeResponse(json.dumps({
        "results": [
            {
                "id": "fixture-7",
                "loki_canary": marker,
                "record": "dummy-lab-data",
                "password": "must-not-be-returned",
                "email": "user@example.test",
            }
        ]
    }).encode())

    result = await security_tools.verify_lab_data_access(
        url="https://lab.example.test/api/records?id=1",
        canary_marker=marker,
        parameter="id",
        payload="' OR 1=1--",
    )

    assert "VERIFIED — LAB DATA ACCESS CONFIRMED" in result
    assert "dummy-lab-data" in result
    assert "must-not-be-returned" not in result
    assert "user@example.test" not in result

    request = _FakeClient.last_request
    assert request["method"] == "GET"
    assert "id=%27+OR+1%3D1--" in request["url"]
    assert marker not in request["url"]
    assert request["options"]["follow_redirects"] is False
    assert request["options"]["trust_env"] is False

    session = lab_context.assessment_store.load_assessment("lab_disposable")
    assert len(session.findings) == 1
    assert session.findings[0].confidence == ConfidenceLevel.CONFIRMED
    assert session.findings[0].evidence_hash


@pytest.mark.asyncio
async def test_lab_probe_does_not_call_target_when_lab_mode_disabled(lab_context):
    lab_context.scope_manager.config.lab_mode_enabled = False
    result = await security_tools.verify_lab_data_access(
        url="https://lab.example.test/api/records",
        canary_marker=_marker(),
    )
    assert "operator must explicitly enable" in result
    assert _FakeClient.last_request is None


@pytest.mark.asyncio
async def test_lab_probe_does_not_claim_success_without_canary(lab_context):
    _FakeClient.response = _FakeResponse(json.dumps({
        "message": "SQL syntax error",
        "results": [{"id": 1, "name": "not the canary"}],
    }).encode())

    result = await security_tools.verify_lab_data_access(
        url="https://lab.example.test/api/records",
        canary_marker=_marker(),
    )
    assert "NOT VERIFIED" in result
    session = lab_context.assessment_store.load_assessment("lab_disposable")
    assert session.findings == []


@pytest.mark.asyncio
async def test_lab_probe_rejects_out_of_scope_target(lab_context):
    result = await security_tools.verify_lab_data_access(
        url="https://outside.example.test/api/records",
        canary_marker=_marker(),
    )
    assert "outside the active scope" in result
    assert _FakeClient.last_request is None


@pytest.mark.asyncio
async def test_lab_probe_rejects_canary_reflection_and_redirects(lab_context):
    marker = _marker()
    _FakeClient.response = _FakeResponse(
        json.dumps({"data": [{"loki_canary": marker}]}).encode(),
        status=302,
    )
    redirected = await security_tools.verify_lab_data_access(
        url="https://lab.example.test/api/records",
        canary_marker=marker,
    )
    assert "redirects are disabled" in redirected.lower()

    reflected = await security_tools.verify_lab_data_access(
        url=f"https://lab.example.test/api/records?marker={marker}",
        canary_marker=marker,
    )
    assert "marker must not be present" in reflected.lower()
