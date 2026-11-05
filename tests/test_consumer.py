"""The queue consumer, against fakes that behave like SQS and Security Hub."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hubtriage import cases, cli, consumer, hub, llm
from hubtriage.clients import Cassette

CASE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic" / "port-probe-ssh-open"


def raw_finding() -> dict:
    return json.loads((CASE / "finding.json").read_text(encoding="utf-8"))


def event(*findings: dict) -> str:
    return json.dumps({
        "source": "aws.securityhub",
        "detail-type": "Security Hub Findings - Imported",
        "detail": {"findings": list(findings)},
    })


class FakeSqs:
    """Receiving hides a message; only deleting removes it. Redeliver with `redeliver()`."""

    def __init__(self, *bodies: str):
        self.visible = [{"Body": b, "ReceiptHandle": f"r{i}"} for i, b in enumerate(bodies)]
        self.hidden: list[dict] = []
        self.deleted: list[str] = []
        self.receive_args: list[dict] = []

    def receive_message(self, **kw):
        self.receive_args.append(kw)
        if not self.visible:
            return {}
        message = self.visible.pop(0)
        self.hidden.append(message)
        return {"Messages": [message]}

    def delete_message(self, QueueUrl, ReceiptHandle):
        self.deleted.append(ReceiptHandle)
        self.hidden = [m for m in self.hidden if m["ReceiptHandle"] != ReceiptHandle]

    def redeliver(self):
        self.visible, self.hidden = self.hidden, []


class FakeHub:
    """Holds one finding. A write-back moves it out of NEW, as the real one would."""

    def __init__(self, *findings: dict):
        self.findings = {f["Id"]: f for f in findings}
        self.updates: list[dict] = []
        self.unprocessed: list[dict] = []

    def get_findings(self, Filters, MaxResults):
        found = self.findings.get(Filters["Id"][0]["Value"])
        return {"Findings": [found] if found else []}

    def batch_update_findings(self, **update):
        self.updates.append(update)
        if self.unprocessed:
            return {"UnprocessedFindings": self.unprocessed}
        for identifier in update["FindingIdentifiers"]:
            self.findings[identifier["Id"]]["Workflow"] = update["Workflow"]
        return {"ProcessedFindings": update["FindingIdentifiers"], "UnprocessedFindings": []}


def replay(out: Path):
    def run(current: dict):
        return cases.record(
            current, out, Cassette(CASE / "cassette"), llm.recorded(CASE / "model_output.json")
        )

    return run


def consume(sqs: FakeSqs, securityhub: FakeHub, out: Path, **kw) -> consumer.Tally:
    return consumer.drain(
        sqs,
        "https://sqs.example/q",
        lambda raw: consumer.triage_new(securityhub, raw, replay(out), log=lambda _: None, **kw),
        log=lambda _: None,
    )


# ------------------------------------------------------------------ messages


def test_findings_come_out_of_the_eventbridge_envelope():
    assert consumer.findings_in(event({"Id": "a"}, {"Id": "b"})) == [{"Id": "a"}, {"Id": "b"}]


@pytest.mark.parametrize("body", ["not json", "[]", '{"detail": {}}', event()])
def test_a_body_that_is_not_a_findings_event_is_refused(body):
    with pytest.raises(consumer.BadMessage):
        consumer.findings_in(body)


# ------------------------------------------------------------------ the queue


def test_a_handled_message_is_deleted_and_an_empty_queue_ends_the_run():
    sqs = FakeSqs(event({"Id": "a"}))
    seen = []
    tally = consumer.drain(sqs, "q", seen.append)
    assert seen == [{"Id": "a"}] and sqs.deleted == ["r0"]
    assert (tally.messages, tally.failed) == (1, 0)
    assert sqs.receive_args[0]["VisibilityTimeout"] == consumer.VISIBILITY_SECONDS


def test_a_failed_message_stays_on_the_queue_and_the_next_one_still_runs():
    sqs = FakeSqs(event({"Id": "bad"}), event({"Id": "good"}))
    logged = []

    def handle(raw):
        if raw["Id"] == "bad":
            raise RuntimeError("boom")

    tally = consumer.drain(sqs, "q", handle, log=logged.append)
    assert sqs.deleted == ["r1"]
    assert [m["ReceiptHandle"] for m in sqs.hidden] == ["r0"]
    assert tally.failed == 1 and "RuntimeError: boom" in logged[0]


def test_a_malformed_message_is_left_for_the_dead_letter_queue():
    sqs = FakeSqs("not json")
    tally = consumer.drain(sqs, "q", lambda raw: None, log=lambda _: None)
    assert sqs.deleted == [] and tally.failed == 1


def test_a_run_that_does_not_write_back_deletes_nothing():
    sqs = FakeSqs(event({"Id": "a"}))
    consumer.drain(sqs, "q", lambda raw: None, delete=False)
    assert sqs.deleted == []


def test_expired_credentials_stop_the_run_instead_of_burning_receives():
    class Expired:
        def receive_message(self, **kw):
            raise PermissionError("ExpiredToken")

    with pytest.raises(PermissionError):
        consumer.drain(Expired(), "q", lambda raw: None)


def test_a_network_failure_while_handling_stops_the_run_and_keeps_every_message():
    exceptions = pytest.importorskip("botocore.exceptions")
    sqs = FakeSqs(event({"Id": "a"}), event({"Id": "b"}))

    def handle(raw):
        raise exceptions.EndpointConnectionError(endpoint_url="https://sts.example")

    with pytest.raises(exceptions.EndpointConnectionError):
        consumer.drain(sqs, "q", handle)
    assert sqs.deleted == [] and len(sqs.visible) == 1  # the second was never received


# ------------------------------------------------------------------ the hub


def test_still_new_reads_the_finding_as_it_is_now():
    doc = raw_finding()
    securityhub = FakeHub(doc)
    assert hub.still_new(securityhub, doc["Id"], doc["ProductArn"]) == doc
    doc["Workflow"] = {"Status": "RESOLVED"}
    assert hub.still_new(securityhub, doc["Id"], doc["ProductArn"]) is None
    doc["Workflow"] = {"Status": "NEW"}
    doc["RecordState"] = "ARCHIVED"
    assert hub.still_new(securityhub, doc["Id"], doc["ProductArn"]) is None


def test_a_finding_the_hub_does_not_have_is_an_error():
    waits = []
    with pytest.raises(hub.NotInHub):
        hub.still_new(
            FakeHub(), "missing", "arn:aws:securityhub:::product/aws/guardduty", sleep=waits.append
        )
    assert len(waits) == hub.READ_ATTEMPTS - 1


def test_a_finding_the_hub_cannot_return_yet_is_read_again():
    doc = raw_finding()
    securityhub = FakeHub(doc)
    empty_reads = [{"Findings": []}, {"Findings": []}]
    real_read = securityhub.get_findings

    def lagging(Filters, MaxResults):
        return empty_reads.pop() if empty_reads else real_read(Filters, MaxResults)

    securityhub.get_findings = lagging
    waits = []
    assert hub.still_new(securityhub, doc["Id"], doc["ProductArn"], sleep=waits.append) == doc
    assert waits == [hub.READ_WAIT_SECONDS] * 2


# ------------------------------------------------------------------ end to end


def test_an_event_becomes_a_verdict_and_a_recorded_case(tmp_path):
    doc = raw_finding()
    sqs, securityhub = FakeSqs(event(doc)), FakeHub(doc)
    tally = consume(sqs, securityhub, tmp_path)
    assert (tally.messages, tally.failed) == (1, 0) and sqs.deleted == ["r0"]
    (update,) = securityhub.updates
    assert update["Workflow"] == {"Status": "NOTIFIED"}
    assert update["VerificationState"] == "TRUE_POSITIVE"
    (case_dir,) = tmp_path.iterdir()
    assert (case_dir / "finding.json").exists() and (case_dir / "model_output.json").exists()
    assert json.loads((case_dir / "cassette" / "index.json").read_text())


def test_a_second_delivery_of_an_answered_finding_writes_nothing(tmp_path):
    doc = raw_finding()
    body = event(doc)
    sqs, securityhub = FakeSqs(body, body), FakeHub(doc)
    tally = consume(sqs, securityhub, tmp_path)
    assert len(securityhub.updates) == 1
    assert tally.messages == 2 and sqs.deleted == ["r0", "r1"]


def test_a_finding_a_person_closed_while_queued_is_left_alone(tmp_path):
    doc = raw_finding()
    closed = {**doc, "Workflow": {"Status": "RESOLVED"}}
    sqs, securityhub = FakeSqs(event(doc)), FakeHub(closed)
    consume(sqs, securityhub, tmp_path)
    assert securityhub.updates == [] and sqs.deleted == ["r0"]


def test_another_products_finding_in_the_event_is_skipped(tmp_path):
    doc = raw_finding()
    other = {**doc, "Id": "other", "ProductName": "Inspector"}
    sqs, securityhub = FakeSqs(event(other, doc)), FakeHub(doc)
    tally = consume(sqs, securityhub, tmp_path)
    assert tally.failed == 0 and len(securityhub.updates) == 1


def test_a_rejected_write_back_keeps_the_message_and_the_retry_starts_clean(tmp_path):
    doc = raw_finding()
    sqs, securityhub = FakeSqs(event(doc)), FakeHub(doc)
    securityhub.unprocessed = [{"ErrorCode": "x"}]
    assert consume(sqs, securityhub, tmp_path).failed == 1
    assert sqs.deleted == []
    (case_dir,) = tmp_path.iterdir()
    first_index = json.loads((case_dir / "cassette" / "index.json").read_text())

    securityhub.unprocessed = []
    sqs.redeliver()
    assert consume(sqs, securityhub, tmp_path).failed == 0
    assert sqs.deleted == ["r0"]
    assert json.loads((case_dir / "cassette" / "index.json").read_text()) == first_index


def test_no_write_back_leaves_the_finding_and_the_message_alone(tmp_path):
    doc = raw_finding()
    sqs, securityhub = FakeSqs(event(doc)), FakeHub(doc)
    consumer.drain(
        sqs,
        "q",
        lambda raw: consumer.triage_new(securityhub, raw, replay(tmp_path), write_back=False),
        delete=False,
    )
    assert securityhub.updates == [] and sqs.deleted == []


def test_consume_needs_a_queue(monkeypatch):
    monkeypatch.delenv("HUBTRIAGE_QUEUE_URL", raising=False)
    with pytest.raises(SystemExit, match="no queue"):
        cli.main(["consume"])
