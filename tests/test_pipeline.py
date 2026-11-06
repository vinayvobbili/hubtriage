"""The pieces between a finding and a write-back request, each on its own."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from witness.store import Store

from hubtriage import evidence, verdict
from hubtriage.clients import Cassette, CassetteMiss, Recorder
from hubtriage.findings import SAMPLE_FIELD, Finding
from hubtriage.triage import NoModelAnswered, require_answer, triage
from hubtriage.writeback import NOTE_LIMIT, build_update

SYNTHETIC = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"


def finding(case: str) -> Finding:
    return Finding.load(SYNTHETIC / case / "finding.json")


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


# ------------------------------------------------------------------ findings


def test_reads_resources_from_asff():
    f = finding("port-probe-ssh-open")
    assert f.instance_ids() == ["i-0a1b2c3d4e5f60718"]
    assert f.access_keys() == []
    key = finding("enrich-role-discovery").access_keys()[0]
    assert (key.access_key_id, key.principal_name, key.principal_type) == (
        "ASIA-EXAMPLE-ENRICH", "hubtriage-enrich", "AssumedRole",
    )


def test_refuses_a_document_that_is_not_a_finding():
    with pytest.raises(ValueError, match="AwsAccountId"):
        Finding.from_asff({"Id": "x", "ProductArn": "y"})


def sample_of(case: str, mark: str | None = "true", **changes) -> Finding:
    doc = json.loads((SYNTHETIC / case / "finding.json").read_text())
    if mark is not None:
        doc.setdefault("ProductFields", {})[SAMPLE_FIELD] = mark
    return Finding.from_asff({**doc, **changes})


def test_only_guardduty_s_mark_makes_a_sample():
    assert sample_of("port-probe-ssh-open").is_sample
    assert not sample_of("port-probe-ssh-open", mark="false").is_sample
    # A placeholder name is something an attacker can choose; the mark is GuardDuty's.
    assert not sample_of("port-probe-ssh-open", mark=None, Title="GeneratedFindingInstanceId").is_sample
    # ASFF's own field, which some GuardDuty sample types carry without GuardDuty's.
    assert sample_of("port-probe-ssh-open", mark=None, Sample=True).is_sample
    assert not sample_of("port-probe-ssh-open", mark=None, Sample="false").is_sample


def test_a_sample_is_decided_before_any_lookup_or_model(store):
    def nobody(*_):
        raise AssertionError("a sample must not reach AWS or a model")

    class NoAws:
        def __getattr__(self, name):
            return nobody

    result = triage(store, NoAws(), nobody, sample_of("port-probe-ssh-open"), mode="live")
    assert result.decision.verdict == verdict.SAMPLE
    assert result.answer == "" and require_answer(result) is result
    assert result.update["VerificationState"] == "FALSE_POSITIVE"
    assert result.update["Workflow"] == {"Status": "NOTIFIED"}
    assert result.update["UserDefinedFields"]["hubtriage_verdict"] == "sample"
    assert list(result.evidence.kinds().values()) == ["finding"]


def test_a_finding_with_no_answer_still_stops_a_live_triage(store):
    result = triage(store, Cassette(SYNTHETIC / "port-probe-ssh-open" / "cassette"),
                    lambda prompt: "", finding("port-probe-ssh-open"))
    with pytest.raises(NoModelAnswered):
        require_answer(result)


# ------------------------------------------------------------------ the plan


def test_root_is_looked_up_by_username_not_by_key():
    lookups = evidence.plan(finding("root-login-misread"))
    assert len(lookups) == 1
    attrs = lookups[0].params["LookupAttributes"]
    assert attrs == [{"AttributeKey": "Username", "AttributeValue": "root"}]


def test_cloudtrail_window_brackets_the_finding():
    params = evidence.plan(finding("root-login-misread"))[0].params
    assert params["StartTime"] == "2026-10-16T08:12:44+00:00"
    assert params["EndTime"] == "2026-10-16T10:12:44+00:00"


def test_an_instance_raises_its_security_groups():
    first = evidence.plan(finding("port-probe-ssh-open"))[0]
    response = json.loads((SYNTHETIC / "port-probe-ssh-open/cassette/00-ec2.DescribeInstances.json").read_text())
    (follow,) = evidence.follow_ups(first, response)
    assert follow.operation == "DescribeSecurityGroups"
    assert follow.params == {"GroupIds": ["sg-0123abcd4567ef890"]}


def test_an_instance_s_history_is_asked_with_no_time_bounds():
    history = evidence.plan(finding("port-probe-ssh-open"))[1]
    assert (history.operation, history.kind) == ("LookupEvents", "instance_history")
    assert history.params["LookupAttributes"] == [
        {"AttributeKey": "ResourceName", "AttributeValue": "i-0a1b2c3d4e5f60718"}
    ]
    # A termination after the finding is the point; a window around the finding would miss it.
    assert "StartTime" not in history.params and "EndTime" not in history.params


def test_a_gone_instance_comes_with_who_terminated_it(store):
    case = SYNTHETIC / "brute-force-instance-gone"
    found = evidence.collect(store, Cassette(case / "cassette"), Finding.load(case / "finding.json"))
    assert "ec2_instance_empty" in found.kinds().values()
    (event,) = store.query_records(kind="instance_history")
    assert event["fields"]["CloudTrailEvent.eventName"] == "TerminateInstances"
    assert event["fields"]["CloudTrailEvent.userIdentity.userName"] == "ops-oncall"


def test_cloudtrail_bodies_are_decoded_and_traced_to_the_raw_response(store):
    f = finding("root-login-misread")
    ev = evidence.collect(store, Cassette(SYNTHETIC / "root-login-misread/cassette"), f)
    (ct,) = [c for c in ev.collected if c.lookup.service == "cloudtrail"]
    record = store.get_record(ct.record_ids[0])
    assert record["fields"]["CloudTrailEvent.sourceIPAddress"] == "198.51.100.7"
    call = store.get_tool_call(ct.tool_call_id)
    assert call["evidence_sha256"] and call["evidence_sha256"] != call["output_sha256"]


def test_an_empty_answer_is_recorded_not_dropped(store, tmp_path):
    class Gone:
        def call(self, service, operation, params, *, account_id, region):
            if operation == "DescribeInstances":
                return {"Reservations": []}
            if operation == "LookupEvents":
                return {"Events": []}
            raise AssertionError("no follow-up for an instance that is not there")

    ev = evidence.collect(store, Gone(), finding("port-probe-ssh-open"))
    c, history = ev.collected
    assert (c.kind, history.kind) == ("ec2_instance_empty", "instance_history_empty")
    assert store.get_record(c.record_ids[0])["fields"] == {"Reservations": "[]"}  # witness keeps an empty container as a leaf


def test_a_failed_lookup_is_kept_as_an_error(store):
    class Denied:
        def call(self, *a, **k):
            raise PermissionError("AccessDenied")

    ev = evidence.collect(store, Denied(), finding("port-probe-ssh-open"))
    assert [c.error for c in ev.collected] == ["AccessDenied", "AccessDenied"]


# ------------------------------------------------------------------ cassettes


def test_recorder_writes_what_cassette_replays(tmp_path):
    class Live:
        def call(self, service, operation, params, *, account_id, region):
            return {"Answer": 42, "ResponseMetadata": {"RequestId": "differs every run"}}

    rec = Recorder(Live(), tmp_path)
    got = rec.call("svc", "Op", {"A": 1}, account_id="111122223333", region="us-east-1")
    assert got == {"Answer": 42}
    replayed = Cassette(tmp_path).call("svc", "Op", {"A": 1}, account_id="111122223333", region="us-east-1")
    assert replayed == {"Answer": 42}


def test_an_unrecorded_call_is_a_miss_not_a_guess(tmp_path):
    with pytest.raises(CassetteMiss):
        Cassette(tmp_path).call("svc", "Op", {}, account_id="1", region="r")


# ------------------------------------------------------------------ verdicts


def ingest_one(store) -> str:
    _, (rid,), _ = evidence.ingest_text(
        store, tool="t", kind="k", text='{"port": 22}', records_at=None, host="h",
        evidence_path="test",
    )
    return rid


def answer(v: str, *claims: tuple[str, str, object], rid: str) -> str:
    return json.dumps({
        "verdict": v,
        "summary": "s",
        "claims": [{"text": t, "bindings": [{"record_id": rid, "field": f, "value": val}]}
                   for t, f, val in claims],
    })


@pytest.mark.parametrize("text", ["not json", "[]", '{"verdict": "maybe"}',
                                  '{"verdict": "benign", "claims": [{"text": "x", "bindings": [{}]}]}'])
def test_off_schema_answers_go_to_a_human(store, text):
    d = verdict.decide(store, text, host="h")
    assert d.verdict == verdict.NEEDS_HUMAN and d.model_verdict is None and d.reason


def test_fenced_json_is_read():
    v = verdict.parse('```json\n{"verdict": "benign", "claims": []}\n```')
    assert v.verdict == "benign"


def test_no_admitted_claim_means_a_human(store):
    rid = ingest_one(store)
    d = verdict.decide(store, answer("true_positive", ("p", "port", 23), rid=rid), host="h")
    assert d.verdict == verdict.NEEDS_HUMAN and len(d.refused) == 1


def test_unbound_claims_are_not_evidence(store):
    d = verdict.decide(store, json.dumps({"verdict": "benign", "claims": [{"text": "trust me"}]}), host="h")
    assert d.verdict == verdict.NEEDS_HUMAN


def test_benign_needs_every_claim(store):
    rid = ingest_one(store)
    d = verdict.decide(store, answer("benign", ("ok", "port", 22), ("bad", "port", 23), rid=rid), host="h")
    assert d.verdict == verdict.NEEDS_HUMAN and d.model_verdict == "benign"


@pytest.mark.parametrize(("shown_kind", "stands"), [
    ("finding", True),  # no CloudTrail asked: the finding is what happened, and it was cited
    ("iam_role", False),  # what was approved, cited alone
])
def test_benign_must_cite_what_happened(store, shown_kind, stands):
    rid = ingest_one(store)
    d = verdict.decide(store, answer("benign", ("ok", "port", 22), rid=rid), host="h", shown={rid: shown_kind})
    assert (d.verdict == verdict.BENIGN) is stands
    assert stands or "what happened" in d.reason


def test_when_cloudtrail_was_asked_a_benign_must_cite_its_answer_even_empty():
    shown = {"f": "finding", "r": "iam_role", "c": "cloudtrail_event_empty"}
    assert verdict.what_happened(shown) == {"cloudtrail_event_empty"}
    assert verdict.what_happened({"f": "finding", "g": "ec2_security_group"}) == {"finding"}
    # An instance's history says who launched or stopped it, not what the finding saw.
    assert verdict.what_happened({"f": "finding", "h": "instance_history_empty"}) == {"finding"}


def test_a_true_positive_need_not_cite_what_happened(store):
    rid = ingest_one(store)
    d = verdict.decide(store, answer("true_positive", ("ok", "port", 22), rid=rid), host="h",
                       shown={rid: "iam_role", "other": "cloudtrail_event"})
    assert d.verdict == verdict.TRUE_POSITIVE


def test_true_positive_survives_a_refused_claim(store):
    rid = ingest_one(store)
    d = verdict.decide(store, answer("true_positive", ("ok", "port", 22), ("bad", "port", 23), rid=rid), host="h")
    assert d.verdict == verdict.TRUE_POSITIVE
    assert [o.claim.text for o in d.admitted] == ["ok"]


# ------------------------------------------------------------------ write-back


def test_note_carries_admitted_claims_only(store):
    rid = ingest_one(store)
    d = verdict.decide(store, answer("true_positive", ("port 22 is open", "port", 22),
                                     ("port 23 is open", "port", 23), rid=rid), host="h")
    d.summary = "port 23 is open, said the summary"
    update = build_update(finding("port-probe-ssh-open"), d, store.head())
    note = update["Note"]["Text"]
    assert "port 22 is open" in note and "23" not in note
    assert update["VerificationState"] == "TRUE_POSITIVE"
    assert update["Workflow"] == {"Status": "NOTIFIED"}


def test_note_fits_security_hubs_limit(store):
    rid = ingest_one(store)
    d = verdict.decide(store, answer("true_positive", *[("x" * 200, "port", 22)] * 5, rid=rid), host="h")
    note = build_update(finding("port-probe-ssh-open"), d, store.head())["Note"]["Text"]
    assert len(note) <= NOTE_LIMIT and note.endswith("]")
