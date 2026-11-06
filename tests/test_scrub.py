"""Scrubbing a recorded case: nothing real survives, and the case still replays the same."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from witness.store import Store

from hubtriage import cases, cli, evidence
from hubtriage.clients import Cassette
from hubtriage.findings import Finding
from hubtriage.scrub import ScrubLeft, Scrubber, leftovers, scrub_case

FIXTURES = Path(cli.FIXTURES)
# Stand-ins for real values, built here so no tracked file holds one of these shapes.
REAL_ACCOUNT = "0987" + "65432109"
REAL_KEY = "AKIA" + "Q7" * 8
REAL_DETECTOR = "f1e2" * 8
REAL_SSO = "AWSReservedSSO_AdministratorAccess_" + "9f8e7d6c5b4a3f2e"


def test_each_identifier_is_replaced_the_same_way_everywhere():
    s = Scrubber()
    one = s.text(f"arn:aws:iam::{REAL_ACCOUNT}:root from 8.8.8.8 key {REAL_KEY} detector/{REAL_DETECTOR}")
    two = s.text(f"{REAL_ACCOUNT} {REAL_KEY} 8.8.8.8")
    assert one == ("arn:aws:iam::111122223333:root from 203.0.113.1 key AKIA-EXAMPLE-1 "
                   "detector/example0000000000000000000000000")
    assert two == "111122223333 AKIA-EXAMPLE-1 203.0.113.1"


def test_what_is_not_identifying_is_kept():
    kept = "0.0.0.0/0 10.0.0.0/16 198.51.100.7 111122223333 aws-cli/2.17.0 2026-10-20T08:01:00Z"
    assert Scrubber().text(kept) == kept


def test_people_and_their_sessions_become_placeholders():
    out = Scrubber().text(f"{REAL_SSO}/dana.lee@initech.com via 2600:1f18:aa:bb::5 in o-a1b2c3d4e5")
    assert out == ("AWSReservedSSO_AdministratorAccess_0000000000000000/person1@example.com"
                   " via 2001:db8::1 in o-exampleorg01")
    assert not leftovers(out)


def test_leftovers_name_what_still_looks_real():
    found = leftovers(f"{REAL_ACCOUNT} 8.8.4.4 {REAL_SSO} sam@globex.com")
    assert set(found) == {REAL_ACCOUNT, "8.8.4.4", REAL_SSO, "sam@globex.com"}


def as_if_real(case: Path, tmp_path: Path) -> Path:
    """A made-up case with its placeholders swapped for real-looking values, like a fresh recording."""
    copy = tmp_path / "recorded" / case.name
    shutil.copytree(case, copy)
    for path in copy.rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("111122223333", REAL_ACCOUNT).replace("198.51.100.7", "8.8.4.4"),
                        encoding="utf-8")
    return copy


def records(case: Path) -> list[tuple[str, dict]]:
    store = Store(case.parent / f"{case.name}.db")
    try:
        evidence.collect(store, Cassette(case / "cassette"), Finding.load(case / "finding.json"))
        return [(r["kind"], r["fields"]) for r in store.query_records()]
    finally:
        store.close()


def test_a_scrubbed_case_replays_to_the_same_records(tmp_path):
    original = FIXTURES / "synthetic" / "root-login-misread"
    recorded = as_if_real(original, tmp_path)
    assert REAL_ACCOUNT in (recorded / "finding.json").read_text(encoding="utf-8")

    counts = scrub_case(recorded, tmp_path / "scrubbed")
    assert counts["account"] == 1 and counts["ipv4"] == 1
    scrubbed = tmp_path / "scrubbed"
    assert not (scrubbed / "model_output.json").exists()
    assert not any(leftovers(p.read_text(encoding="utf-8")) for p in scrubbed.rglob("*.json"))
    # The real address became the first placeholder, so compare on kinds and field names.
    assert [(k, sorted(f)) for k, f in records(scrubbed)] == [(k, sorted(f)) for k, f in records(original)]


def test_a_case_that_cannot_be_cleaned_is_refused_and_nothing_is_written(tmp_path, monkeypatch):
    recorded = as_if_real(FIXTURES / "synthetic" / "root-login-misread", tmp_path)
    monkeypatch.setattr(Scrubber, "text", lambda self, text: text)  # a scrub that misses everything
    with pytest.raises(ScrubLeft, match=REAL_ACCOUNT):
        scrub_case(recorded, tmp_path / "scrubbed")
    assert not (tmp_path / "scrubbed").exists()


def test_recording_asks_no_model_and_keeps_every_answer(tmp_path):
    case = FIXTURES / "synthetic" / "ci-user-creates-admin"
    raw = json.loads((case / "finding.json").read_text(encoding="utf-8"))
    directory, collected = cases.record_evidence(raw, tmp_path, Cassette(case / "cassette"))
    assert not (directory / "model_output.json").exists()
    assert [c.kind for c in collected] == ["iam_user", "iam_attached_policy", "cloudtrail_event"]
    assert records(directory) == records(case)
