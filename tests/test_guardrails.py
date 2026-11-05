"""The IAM check, against a fake hub that refuses what the rules would."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from hubtriage import cli, guardrails, hub

AGENT_TF = Path(__file__).resolve().parents[1] / "terraform" / "10-security" / "agent.tf"

SAMPLE = {
    "Id": "arn:aws:guardduty:us-east-1:111122223333:detector/d/finding/f",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
    "ProductFields": {"threatName": "GeneratedFindingThreatName"},
}
REAL = {**SAMPLE, "ProductFields": {"threatName": "Tor"}}


class Refused(Exception):
    def __init__(self, code: str):
        self.response = {"Error": {"Code": code}}


class RuleHub:
    """Refuses every write but a note, unless told a named field gets through."""

    def __init__(self, *, leaks: str = "", code: str = "AccessDeniedException"):
        self.leaks = leaks
        self.code = code
        self.writes: list[dict] = []

    def batch_update_findings(self, FindingIdentifiers, **change):
        self.writes.append(change)
        if "Note" in change or self.leaks in change:
            return {"ProcessedFindings": FindingIdentifiers, "UnprocessedFindings": []}
        raise Refused(self.code)


def test_every_rule_holding_passes_and_the_note_goes_through():
    probes = guardrails.check(RuleHub(), SAMPLE)
    assert all(p.ok for p in probes)
    assert [p.name for p in probes if p.got == "allowed"] == ["Note"]


def test_a_rule_that_lets_a_close_through_fails_the_check():
    probes = {p.name: p for p in guardrails.check(RuleHub(leaks="Workflow"), SAMPLE)}
    assert not probes["Workflow.Status=RESOLVED"].ok
    assert probes["Workflow.Status=RESOLVED"].got == "allowed"


def test_a_role_with_no_access_at_all_fails_on_the_control():
    class NoAccess(RuleHub):
        def batch_update_findings(self, FindingIdentifiers, **change):
            raise Refused("AccessDeniedException")

    (control,) = [p for p in guardrails.check(NoAccess(), SAMPLE) if p.name == "Note"]
    assert not control.ok and control.got == "denied"


def test_an_error_that_is_not_a_refusal_is_not_counted_as_one():
    probes = guardrails.check(RuleHub(code="InvalidInputException"), SAMPLE)
    assert {p.got for p in probes if p.name != "Note"} == {"InvalidInputException"}
    assert not any(p.ok for p in probes if p.name != "Note")


def test_a_real_finding_is_refused_before_any_write():
    securityhub = RuleHub()
    with pytest.raises(guardrails.NotASample):
        guardrails.check(securityhub, REAL)
    assert securityhub.writes == []


def test_a_network_failure_stops_the_check():
    exceptions = pytest.importorskip("botocore.exceptions")

    class Down(RuleHub):
        def batch_update_findings(self, FindingIdentifiers, **change):
            raise exceptions.EndpointConnectionError(endpoint_url="https://securityhub.example")

    with pytest.raises(exceptions.EndpointConnectionError):
        guardrails.check(Down(), SAMPLE)


def test_the_check_covers_every_field_terraform_forbids():
    block = re.search(r"forbidden_fields = \[(.*?)\]", AGENT_TF.read_text(encoding="utf-8"), re.S)
    in_terraform = set(re.findall(r'"([^"]+)"', block.group(1)))
    checked = set(guardrails.forbidden_writes(SAMPLE)) - guardrails.CLOSING
    assert checked == in_terraform


def test_the_command_exits_nonzero_when_a_rule_fails(monkeypatch, capsys):
    boto3 = pytest.importorskip("boto3")
    leaky = RuleHub(leaks="Types")
    monkeypatch.setattr(boto3.Session, "client", lambda self, *a, **kw: leaky)
    monkeypatch.setattr(hub, "read", lambda securityhub, finding_id: SAMPLE)
    assert cli.main(["check-iam", "--finding-id", SAMPLE["Id"]]) == 1
    assert "FAIL" in capsys.readouterr().out
