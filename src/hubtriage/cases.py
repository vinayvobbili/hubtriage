"""The labeled set: findings with recorded evidence, a recorded answer and a label.

A case is a directory:

    finding.json        the ASFF finding as Security Hub returned it
    cassette/           every AWS response the plan asks for (see clients.py)
    model_output.json   a model's answer, replayed by the `recorded` judge
    label.json          {"verdict": ..., "refused": n, "source": ...}

`label.json` says what the case *should* come to and where it came from.
`verdict` is the right triage verdict, which a live model is scored against.
`refused`, and `replay_verdict` when it differs from `verdict`, are what the
recorded answer must come to: a case written to show the gate catching a
misread has an answer that is wrong on purpose, so its replay ends somewhere
else than a correct reading would. Cases
under fixtures/synthetic were written by hand to exercise the gate - their model
answers are not a model's, and nothing measured on them is a statement about
any model. Cases recorded from a real account say so in `source`.

Running the set with a live judge (`hubtriage eval --judge env`) asks a real model
for each answer instead, and that is the accuracy number worth reporting.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from witness.store import Store

from .clients import Cassette, Client, Recorder
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
    def answered(self) -> bool:
        return bool(self.result.answer)

    @property
    def correct(self) -> bool:
        # A model that never answered becomes needs_human, which is right for a live
        # finding and would score as a correct verdict here on a needs_human case.
        return self.answered and self.result.decision.verdict == self.case.label["verdict"]

    @property
    def refused_as_expected(self) -> bool:
        expected = self.case.label.get("refused")
        return expected is None or expected == len(self.result.decision.refused)

    @property
    def replayed_as_labeled(self) -> bool:
        """For the recorded answer: did the gate take it where the label says it goes."""
        expected = self.case.label.get("replay_verdict", self.case.label["verdict"])
        return self.result.decision.verdict == expected and self.refused_as_expected


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


def record(raw: dict, out: str | Path, live: Client, judge: Judge) -> Result:
    """Triage a live finding and keep it as a case directory, ready to be labeled.

    A second attempt at the same finding starts over: the queue redelivers what
    failed, and evidence from a run that failed halfway is not evidence for this one.
    """
    finding = Finding.from_asff(raw)
    directory = Path(out) / finding.id.rsplit("/", 1)[-1][:32]
    directory.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(directory / "cassette", ignore_errors=True)
    for leftover in directory.glob("case.db*"):
        leftover.unlink()
    (directory / "finding.json").write_text(json.dumps(raw, indent=2, default=str) + "\n")
    store = Store(directory / "case.db")
    try:
        result = triage(store, Recorder(live, directory / "cassette"), judge, finding, mode="live")
    finally:
        store.close()
    (directory / "model_output.json").write_text(result.answer, encoding="utf-8")
    return result


def summarize(outcomes: list[Outcome]) -> dict:
    claims = sum(len(o.result.decision.outcomes) for o in outcomes)
    refused = sum(len(o.result.decision.refused) for o in outcomes)
    return {
        "cases": len(outcomes),
        "no_answer": sum(not o.answered for o in outcomes),
        "correct": sum(o.correct for o in outcomes),
        "claims": claims,
        "refused": refused,
    }
