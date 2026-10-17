"""The labeled set: findings with recorded evidence, a recorded answer and a label.

A case is a directory:

    finding.json        the ASFF finding as Security Hub returned it
    cassette/           every AWS response the plan asks for (see clients.py)
    model_output.json   a model's answer, replayed by the `recorded` judge
    label.json          {"verdict": ..., "refused": n, "source": ...}

`label.json` says what the case *should* come to and where it came from. Cases
under fixtures/synthetic were written by hand to exercise the gate - their model
answers are not a model's, and nothing measured on them is a statement about
any model. Cases recorded from a real account say so in `source`.

Running the set with a live judge (`hubtriage eval --judge env`) asks a real model
for each answer instead, and that is the accuracy number worth reporting.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from witness.store import Store

from .clients import Cassette
from .findings import Finding
from .llm import Judge, recorded
from .triage import Result, triage


@dataclass
class Case:
    name: str
    directory: Path
    label: dict

    @property
    def finding(self) -> Finding:
        return Finding.load(self.directory / "finding.json")


@dataclass
class Outcome:
    case: Case
    result: Result

    @property
    def correct(self) -> bool:
        return self.result.decision.verdict == self.case.label["verdict"]

    @property
    def refused_as_expected(self) -> bool:
        expected = self.case.label.get("refused")
        return expected is None or expected == len(self.result.decision.refused)


def discover(root: str | Path) -> list[Case]:
    return [
        Case(path.parent.name, path.parent, json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(Path(root).rglob("label.json"))
    ]


def run(case: Case, judge: Judge | None = None, store_dir: str | Path | None = None) -> Outcome:
    """Triage one case in a fresh store. Cases never share evidence."""
    judge = judge or recorded(case.directory / "model_output.json")
    with tempfile.TemporaryDirectory(dir=store_dir) as tmp:
        store = Store(Path(tmp) / "case.db")
        try:
            result = triage(store, Cassette(case.directory / "cassette"), judge, case.finding)
        finally:
            store.close()
    return Outcome(case, result)


def summarize(outcomes: list[Outcome]) -> dict:
    claims = sum(len(o.result.decision.outcomes) for o in outcomes)
    refused = sum(len(o.result.decision.refused) for o in outcomes)
    return {
        "cases": len(outcomes),
        "correct": sum(o.correct for o in outcomes),
        "claims": claims,
        "refused": refused,
    }
