"""Recording and replaying AWS answers, refusals and empty answers included."""

from __future__ import annotations

import pytest

from hubtriage import evidence
from hubtriage.clients import Cassette, RecordedError, Recorder

exceptions = pytest.importorskip("botocore.exceptions")
WHERE = {"account_id": "111122223333", "region": "us-east-1"}


class Aws:
    def __init__(self, answer):
        self.answer = answer

    def call(self, service, operation, params, *, account_id, region):
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_a_refusal_is_recorded_and_replays_as_the_same_refusal(tmp_path):
    denied = exceptions.ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "GetUser")
    with pytest.raises(exceptions.ClientError):
        Recorder(Aws(denied), tmp_path).call("iam", "GetUser", {"UserName": "a"}, **WHERE)

    with pytest.raises(RecordedError) as replayed:
        Cassette(tmp_path).call("iam", "GetUser", {"UserName": "a"}, **WHERE)
    assert replayed.value.code == "AccessDenied" and "not authorized" in str(replayed.value)


def test_no_answer_at_all_is_not_recorded_as_a_refusal(tmp_path):
    throttled = exceptions.ClientError({"Error": {"Code": "ThrottlingException"}}, "LookupEvents")
    with pytest.raises(exceptions.ClientError):
        Recorder(Aws(throttled), tmp_path).call("cloudtrail", "LookupEvents", {}, **WHERE)
    assert not (tmp_path / "index.json").exists()


def test_an_answer_replays_as_recorded(tmp_path):
    Recorder(Aws({"User": {"UserName": "a"}}), tmp_path).call("iam", "GetUser", {"UserName": "a"}, **WHERE)
    assert Cassette(tmp_path).call("iam", "GetUser", {"UserName": "a"}, **WHERE) == {"User": {"UserName": "a"}}


@pytest.mark.parametrize("text", ['{"Events": []}', '{"Reservations": []}'])
def test_an_empty_answer_is_still_a_record_a_claim_can_cite(tmp_path, text):
    from witness.store import Store

    store = Store(tmp_path / "s.db")
    try:
        records_at = "Events" if "Events" in text else "Reservations.0.Instances"
        _, ids, kind = evidence.ingest_text(store, tool="t.Op", kind="thing", text=text, records_at=records_at,
                                            host="111122223333", evidence_path="t:Op")
        assert kind == "thing_empty" and len(ids) == 1
    finally:
        store.close()
