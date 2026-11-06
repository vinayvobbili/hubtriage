"""The generated cases in fixtures/synthetic are exactly what scripts/synth_cases.py writes."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("botocore")
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("synth_cases", ROOT / "scripts" / "synth_cases.py")
synth = importlib.util.module_from_spec(spec)
sys.modules["synth_cases"] = synth  # dataclasses look their module up here
spec.loader.exec_module(synth)


def test_the_committed_cases_match_the_generator(capsys):
    assert synth.main(["--check"]) == 0, capsys.readouterr().out


def test_each_verdict_has_cases_that_must_be_told_apart():
    verdicts = [s.verdict for s in synth.specs()]
    assert {v: verdicts.count(v) for v in set(verdicts)} == {"benign": 4, "true_positive": 7, "needs_human": 4}


def test_the_held_out_set_has_each_verdict_and_its_own_directory():
    held = synth.held_out()
    assert {s.verdict for s in held} == {"benign", "true_positive", "needs_human"}
    assert not {s.name for s in held} & {s.name for s in synth.specs()}
    assert all((ROOT / "fixtures" / "heldout" / s.name / "label.json").exists() for s in held)


def test_the_scanner_twins_differ_only_in_the_host_they_scanned():
    twins = {s.name: s for s in synth.specs() if s.name.startswith("scanner-")}
    inside, outside = twins["scanner-scans-in-scope"], twins["scanner-scans-out-of-scope"]
    assert inside.verdict == "benign" and outside.verdict == "true_positive"
    assert inside.answers["ec2.DescribeInstances"]["Reservations"][0]["Instances"][0]["Tags"] == (
        outside.answers["ec2.DescribeInstances"]["Reservations"][0]["Instances"][0]["Tags"])
