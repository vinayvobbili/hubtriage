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


class NoModelAnswered(RuntimeError):
    """No judge answered. Nothing was concluded, so a live finding has to stay open."""


def require_answer(result: Result) -> Result:
    """For live findings. Writing back would take the finding out of NEW, and the agent
    only picks up NEW, so a model outage would quietly end its triage for good."""
    if not result.answer:
        raise NoModelAnswered(result.decision.reason or "the model's answer was empty")
    return result


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
        decision = verdict.decide(store, answer, host=finding.account_id, shown=evidence.kinds())
    return Result(finding, evidence, text, answer, decision, build_update(finding, decision, store.head()))
