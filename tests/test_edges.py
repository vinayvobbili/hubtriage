"""Judges, the hub calls, and the labeled set as a whole."""

from __future__ import annotations

import pytest

from hubtriage import cases, hub, llm
from hubtriage.cli import FIXTURES, main


def test_failover_asks_the_next_judge_when_one_does_not_answer():
    def down(prompt):
        raise ConnectionRefusedError("host a is off")

    def up(prompt):
        return "answer"

    assert llm.failover(down, up)("p") == "answer"


def test_failover_reports_every_judge_when_none_answers():
    def down(prompt):
        raise TimeoutError("slow")

    with pytest.raises(llm.NoJudgeAnswered, match="slow"):
        llm.failover(down, down)("p")


def test_env_chain_is_local_hosts_in_order_then_bedrock():
    judge = llm.from_env({
        "HUBTRIAGE_LOCAL_URLS": "http://a:8000/v1, http://b:8000/v1",
        "HUBTRIAGE_LOCAL_MODEL": "m",
        "HUBTRIAGE_BEDROCK_MODEL": "some.model",
    })
    assert judge.__name__ == (
        "failover(openai_compatible(http://a:8000/v1), openai_compatible(http://b:8000/v1),"
        " bedrock(some.model))"
    )


def test_env_without_any_backend_is_an_error():
    with pytest.raises(ValueError, match="no judge configured"):
        llm.from_env({})


def test_a_judge_that_never_answers_sends_the_finding_to_a_human():
    case = cases.discover(FIXTURES)[0]

    def down(prompt):
        raise ConnectionRefusedError("all hosts down")

    outcome = cases.run(case, llm.failover(down))
    assert outcome.result.decision.verdict == "needs_human"
    assert "all hosts down" in outcome.result.decision.reason


class FakeHub:
    def __init__(self, unprocessed=()):
        self.unprocessed = list(unprocessed)
        self.sent = []

    def batch_update_findings(self, **kwargs):
        self.sent.append(kwargs)
        return {"ProcessedFindings": [], "UnprocessedFindings": self.unprocessed}


def test_write_back_reads_unprocessed_findings():
    with pytest.raises(hub.WriteBackFailed):
        hub.write_back(FakeHub([{"ErrorCode": "FindingNotFound"}]), {"FindingIdentifiers": []})
    ok = FakeHub()
    hub.write_back(ok, {"FindingIdentifiers": []})
    assert ok.sent == [{"FindingIdentifiers": []}]


def _collect_with(error, tmp_path):
    from witness.store import Store

    from hubtriage import evidence
    from hubtriage.findings import Finding

    class Failing:
        def call(self, *args, **kwargs):
            raise error

    case = next(c for c in cases.discover(FIXTURES) if c.name == "port-probe-ssh-open")
    store = Store(tmp_path / "t.db")
    try:
        return evidence.collect(store, Failing(), Finding.load(case.directory / "finding.json"))
    finally:
        store.close()


@pytest.mark.parametrize(
    "make",
    [
        lambda e: e.EndpointConnectionError(endpoint_url="https://sts.example"),
        lambda e: e.ConnectTimeoutError(endpoint_url="https://sts.example"),
        lambda e: e.NoCredentialsError(),
        lambda e: e.ClientError({"Error": {"Code": "ExpiredToken"}}, "AssumeRole"),
        lambda e: e.ClientError({"Error": {"Code": "ThrottlingException"}}, "LookupEvents"),
    ],
)
def test_a_lookup_that_got_no_answer_stops_the_triage(make, tmp_path):
    exceptions = pytest.importorskip("botocore.exceptions")
    error = make(exceptions)
    with pytest.raises(type(error)):
        _collect_with(error, tmp_path)


def test_a_lookup_aws_refused_is_kept_as_a_gap_in_the_evidence(tmp_path):
    exceptions = pytest.importorskip("botocore.exceptions")
    denied = exceptions.ClientError({"Error": {"Code": "AccessDenied"}}, "DescribeInstances")
    found = _collect_with(denied, tmp_path)
    assert found.collected and all("AccessDenied" in c.error for c in found.collected)


def test_every_labeled_case_comes_out_as_labeled():
    found = cases.discover(FIXTURES)
    assert found, "no labeled cases found"
    for case in found:
        outcome = cases.run(case)
        assert outcome.correct, case.name
        assert outcome.refused_as_expected, case.name


def test_demo_exits_zero(capsys):
    assert main(["demo"]) == 0
    assert "cases came out as labeled" in capsys.readouterr().out


class FakeSession:
    """Stands in for boto3: records every AssumeRole and every API call."""

    def __init__(self, expires_in_minutes=15):
        self.assumed = []
        self.calls = []
        self.expires_in = expires_in_minutes

    def client(self, service, region_name=None):
        session = self

        class C:
            def assume_role(self, **kw):
                from datetime import datetime, timedelta, timezone

                session.assumed.append(kw["RoleArn"])
                exp = datetime.now(timezone.utc) + timedelta(minutes=session.expires_in)
                return {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "s",
                                        "SessionToken": "t", "Expiration": exp}}

            def describe_instances(self, **kw):
                session.calls.append((service, region_name, kw))
                return {"Reservations": []}

        return C()


def test_every_lookup_goes_through_the_enrich_role(monkeypatch):
    pytest.importorskip("boto3")
    import boto3

    from hubtriage.clients import AwsClient

    fake = FakeSession()
    monkeypatch.setattr(boto3, "Session", lambda **kw: fake)
    client = AwsClient(session=fake)
    for _ in range(2):
        client.call("ec2", "DescribeInstances", {"InstanceIds": ["i-1"]},
                    account_id="111122223333", region="us-east-1")
    assert fake.assumed == ["arn:aws:iam::111122223333:role/hubtriage-enrich"]
    assert fake.calls[0] == ("ec2", "us-east-1", {"InstanceIds": ["i-1"]})


def test_a_role_session_near_expiry_is_renewed(monkeypatch):
    pytest.importorskip("boto3")
    import boto3

    from hubtriage.clients import AwsClient

    fake = FakeSession(expires_in_minutes=1)
    monkeypatch.setattr(boto3, "Session", lambda **kw: fake)
    client = AwsClient(session=fake)
    for _ in range(2):
        client.call("ec2", "DescribeInstances", {}, account_id="111122223333", region="us-east-1")
    assert len(fake.assumed) == 2
