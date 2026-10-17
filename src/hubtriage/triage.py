"""One finding, end to end: evidence, prompt, verdict, gate, write-back request."""

from __future__ import annotations

from dataclasses import dataclass

from witness.store import Store

from . import evidence as ev
from . import prompt, verdict
from .clients import Client
from .findings import Finding
from .llm import Judge
from .writeback import build_update


@dataclass
class Result:
    finding: Finding
    evidence: ev.Evidence
    prompt: str
    answer: str
    decision: verdict.Decision
    update: dict


def triage(
    store: Store, client: Client, judge: Judge, finding: Finding, *, mode: str = "replay"
) -> Result:
    evidence = ev.collect(store, client, finding, mode=mode)
    text = prompt.build(store, finding, evidence)
    try:
        answer = judge(text)
    except Exception as e:  # noqa: BLE001 - no answer is a verdict too: a human looks
        answer = ""
        decision = verdict.Decision(verdict.NEEDS_HUMAN, None, "", reason=f"no model answered: {e}")
    else:
        decision = verdict.decide(store, answer, host=finding.account_id)
    return Result(finding, evidence, text, answer, decision, build_update(finding, decision, store.head()))
