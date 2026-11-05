"""The live checks, against one fake that stands in for each AWS client."""

from __future__ import annotations

import pytest

from hubtriage import cli, live

ACCOUNT = "111122223333"
QUEUE_URL = f"https://sqs.example/{ACCOUNT}/hubtriage-findings"
TOPIC = f"arn:aws:sns:us-east-1:{ACCOUNT}:hubtriage-alerts"


class Pages:
    def __init__(self, *pages):
        self.pages = pages

    def paginate(self, **kw):
        return self.pages


class Fake:
    """Every client in one, healthy unless a test changes it."""

    def __init__(self):
        self.standards = []
        self.subscription = "arn:confirmed"
        self.depth = {"hubtriage-findings": ("0", "0"), "hubtriage-findings-dlq": ("0", "0")}
        self.alarm = "OK"
        self.samples = []
        self.alarm_set = []
        self.received = 0

    def client(self, name, region_name=None):
        return self

    def get_enabled_standards(self):
        return {"StandardsSubscriptions": self.standards}

    def list_members(self, **kw):
        if "DetectorId" in kw:
            return {"Members": [{"AccountId": ACCOUNT, "RelationshipStatus": "Enabled"}]}
        return {"Members": [{"AccountId": ACCOUNT, "MemberStatus": "Enabled"}]}

    def list_detectors(self):
        return {"DetectorIds": ["detector"]}

    def get_paginator(self, name):
        if name == "get_findings":
            return Pages({"Findings": [{"ProductName": "GuardDuty"}, {"ProductName": "GuardDuty"}]})
        return Pages({"Topics": [{"TopicArn": TOPIC}]})

    def get_queue_url(self, QueueName):
        return {"QueueUrl": QueueName}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        waiting, handling = self.depth[QueueUrl]
        return {"Attributes": {
            "ApproximateNumberOfMessages": waiting,
            "ApproximateNumberOfMessagesNotVisible": handling,
        }}

    def receive_message(self, **kw):
        self.received += 1
        return {}

    def list_subscriptions_by_topic(self, TopicArn):
        return {"Subscriptions": [{"SubscriptionArn": self.subscription}]}

    def describe_alarms(self, AlarmNames):
        return {"MetricAlarms": [{"StateValue": self.alarm}]}

    def get_caller_identity(self):
        return {"Account": ACCOUNT}

    def list_objects_v2(self, **kw):
        return {"KeyCount": 1}

    def create_sample_findings(self, **kw):
        self.samples.append(kw)

    def set_alarm_state(self, **kw):
        self.alarm_set.append(kw)


def by_name(fake) -> dict:
    return {line.name: line for line in live.status(fake, "us-east-1")}


def test_a_healthy_setup_passes_every_line():
    lines = by_name(Fake())
    assert all(line.ok for line in lines.values())
    assert lines["active findings"].value == "2 GuardDuty"


def test_status_never_receives_a_message():
    fake = Fake()
    live.status(fake, "us-east-1")
    assert fake.received == 0


@pytest.mark.parametrize(
    "change, name",
    [
        (lambda f: setattr(f, "standards", [{"StandardsArn": "x"}]), "standards enabled"),
        (lambda f: setattr(f, "subscription", "PendingConfirmation"), "alert emails"),
        (lambda f: setattr(f, "alarm", "ALARM"), "dead-letter alarm"),
        (lambda f: f.depth.update({"hubtriage-findings-dlq": ("1", "0")}), "dead-letter queue"),
    ],
)
def test_each_problem_fails_its_own_line(change, name):
    fake = Fake()
    change(fake)
    lines = by_name(fake)
    assert not lines[name].ok
    assert [n for n, line in lines.items() if not line.ok] == [name]


def test_samples_go_to_the_accounts_own_detector():
    fake = Fake()
    live.generate_samples(fake)
    assert fake.samples == [{"DetectorId": "detector", "FindingTypes": live.SAMPLE_TYPES}]


def test_waiting_ends_as_soon_as_a_message_arrives():
    fake = Fake()
    naps = []

    def nap(seconds):
        naps.append(seconds)
        fake.depth["hubtriage-findings"] = ("2", "0")

    assert live.wait_for_queue(fake, 900, sleep=nap) == 2
    assert len(naps) == 1


def test_waiting_gives_up_at_the_timeout():
    assert live.wait_for_queue(Fake(), 60, poll=30, sleep=lambda _: None) == 0


def test_a_parked_message_ends_the_wait_as_a_failure():
    fake = Fake()
    fake.depth["hubtriage-findings-dlq"] = ("1", "0")
    with pytest.raises(RuntimeError, match="dead-letter"):
        live.wait_for_queue(fake, 60, sleep=lambda _: None)


def test_the_alert_test_forces_the_alarm():
    fake = Fake()
    live.test_alert(fake)
    assert fake.alarm_set[0]["AlarmName"] == live.ALARM
    assert fake.alarm_set[0]["StateValue"] == "ALARM"


def test_the_status_command_exits_nonzero_on_a_problem(monkeypatch, capsys):
    boto3 = pytest.importorskip("boto3")
    fake = Fake()
    fake.alarm = "ALARM"
    monkeypatch.setattr(boto3, "Session", lambda: fake)
    assert cli.main(["status"]) == 1
    assert "FAIL dead-letter alarm" in capsys.readouterr().out


def test_answers_prints_what_each_model_said(tmp_path, capsys):
    (tmp_path / "case-a.json").write_text(
        '{"verdict": "benign", "summary": "expected", "claims": []}', encoding="utf-8"
    )
    (tmp_path / "case-b.json").write_text("not json", encoding="utf-8")
    assert cli.main(["answers", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "case-a" in out and "benign" in out and "expected" in out
    assert "case-b" in out and "not JSON" in out
