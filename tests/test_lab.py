"""The lab check, against fake EC2 and GuardDuty clients."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from hubtriage import cli, lab

INSTANCE = "i-0123456789abcdef0"
GROUP = "sg-0123456789abcdef0"
MEMBER = "111122223333"


class Pages:
    def __init__(self, *pages):
        self.pages = pages

    def paginate(self, **kw):
        return self.pages


def finding(kind, count=3, sample=False):
    service = {"Count": count, "EventFirstSeen": "2026-01-01T00:00:00Z",
               "EventLastSeen": "2026-01-02T00:00:00Z"}
    if sample:
        service["AdditionalInfo"] = {"Sample": True}
    return {"Type": kind, "Severity": 2, "Service": service}


class Fake:
    """EC2 and GuardDuty in one, the way test_live fakes every client."""

    def __init__(self):
        self.state = "running"
        self.ip = "203.0.113.9"
        self.rules = [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        ]
        self.findings = [finding("Recon:EC2/PortProbeUnprotectedPort")]
        self.usage = [{"DataSource": "CLOUD_TRAIL", "Total": {"Amount": "12.5", "Unit": "Events"}}]
        self.criteria = None

    def client(self, name, region_name=None):
        return self

    def describe_instances(self, InstanceIds):
        box = {"State": {"Name": self.state}, "SecurityGroups": [{"GroupId": GROUP}],
               "LaunchTime": datetime(2026, 1, 1, tzinfo=timezone.utc)}
        if self.ip:
            box["PublicIpAddress"] = self.ip
        return {"Reservations": [{"Instances": [box]}]}

    def describe_security_groups(self, GroupIds):
        return {"SecurityGroups": [{"GroupId": GroupIds[0], "IpPermissions": self.rules}]}

    def list_detectors(self):
        return {"DetectorIds": ["detector"]}

    def get_paginator(self, name):
        assert name == "list_findings"
        return self

    def paginate(self, DetectorId, FindingCriteria):
        self.criteria = FindingCriteria
        return [{"FindingIds": [str(i) for i in range(len(self.findings))]}]

    def get_findings(self, DetectorId, FindingIds):
        return {"Findings": [self.findings[int(i)] for i in FindingIds]}

    def get_detector(self, DetectorId):
        return {"FindingPublishingFrequency": "SIX_HOURS"}

    def list_members(self, **kw):
        return {"Members": [{"AccountId": MEMBER, "RelationshipStatus": "Enabled"}]}

    def get_usage_statistics(self, **kw):
        return {"UsageStatistics": {"SumByDataSource": self.usage}}


def report(fake) -> dict:
    return {line.name: line.value for line in lab.lab(fake, fake, INSTANCE)}


def test_the_report_covers_instance_findings_detector_and_usage():
    out = report(Fake())
    assert out["instance state"] == "running"
    assert out["public IP"] == "203.0.113.9"
    assert out["open to 0.0.0.0/0"] == f"{GROUP} tcp 22"
    assert out["findings"] == "1"
    assert "severity 2, seen 3x" in out["Recon:EC2/PortProbeUnprotectedPort"]
    assert out["publishing frequency"] == "SIX_HOURS"
    assert out["GuardDuty members"] == f"{MEMBER} Enabled"
    assert out["usage CLOUD_TRAIL"] == "12.5 Events"


def test_a_data_source_with_no_usage_says_so():
    assert report(Fake())["usage FLOW_LOGS"] == "no usage"


def test_findings_are_looked_up_by_instance_and_samples_are_left_out():
    fake = Fake()
    fake.findings.append(finding("Backdoor:EC2/C&CActivity.B", sample=True))
    out = report(fake)
    assert out["findings"] == "1"
    assert "Backdoor:EC2/C&CActivity.B" not in out
    assert fake.criteria["Criterion"]["resource.instanceDetails.instanceId"] == {"Eq": [INSTANCE]}


def test_no_findings_and_no_public_address():
    fake = Fake()
    fake.findings, fake.ip, fake.rules = [], None, []
    out = report(fake)
    assert out["findings"] == "none for this instance"
    assert out["public IP"] == "none"
    assert out["open to 0.0.0.0/0"] == "nothing"


def test_the_lab_command_prints_the_report_and_exits_zero(monkeypatch, capsys):
    boto3 = pytest.importorskip("boto3")
    monkeypatch.setattr(boto3, "Session", lambda **kw: Fake())
    assert cli.main(["lab", "--instance", INSTANCE]) == 0
    assert "instance state" in capsys.readouterr().out
