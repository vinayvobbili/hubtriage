"""What the model is asked for, what it said, and what the gate let through.

The model returns a verdict, a one-line summary and a list of claims, each claim
bound to record fields it read. Every claim goes through witness's gate. The
final verdict is then decided by a policy that is asymmetric on purpose:

- **benign** closes the loop on an alert, so it is the expensive direction to be
  wrong in. It stands only if every claim the model made was admitted. One
  refused claim means the model misread the evidence somewhere, and a dismissal
  built on a misreading is sent to a human. It must also cite the record of
  what happened - CloudTrail's answer when CloudTrail was asked, empty or not,
  and otherwise the finding itself - because the gate can check that a claim is
  true but not that the model left nothing out. A dismissal that cites an
  approved scanner's tag and never the address it scanned, or a role's purpose
  and never the empty CloudTrail answer, has every claim admitted and is still
  wrong. Records that only say what a principal could do (its attached
  policies) are not required: they neither show the activity nor approve it.
- **true_positive** escalates, which is the cheap direction. It stands if at
  least one claim was admitted; refused claims are dropped from the note and
  counted.
- **needs_human** stands as it is.

A verdict with no admitted claim at all is needs_human whatever the model said:
nothing it concluded was shown to rest on anything AWS returned.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from witness import Binding, submit_finding
from witness.store import Store

TRUE_POSITIVE = "true_positive"
BENIGN = "benign"
NEEDS_HUMAN = "needs_human"
VERDICTS = (TRUE_POSITIVE, BENIGN, NEEDS_HUMAN)

SCHEMA = {
    "verdict": f"one of {', '.join(VERDICTS)}",
    "summary": "one sentence a responder reads first",
    "claims": [
        {
            "text": "one factual statement the verdict rests on",
            "bindings": [{"record_id": "id from the records", "field": "field name", "value": "exact value"}],
        }
    ],
}


# The same shape as a JSON Schema, for servers that enforce one while decoding. The caps are the
# point: a small model can repeat one sentence until it runs out of tokens, inside a string, and
# the answer never closes. Claims come before the summary so a long summary cannot crowd them out.
JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"enum": list(VERDICTS)},
        "claims": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "maxLength": 300},
                    "bindings": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 6,
                        "items": {
                            "type": "object",
                            "properties": {
                                "record_id": {"type": "string", "maxLength": 64},
                                "field": {"type": "string", "maxLength": 200},
                                "value": {"type": ["string", "number", "boolean", "null"]},
                            },
                            "required": ["record_id", "field", "value"],
                        },
                    },
                },
                "required": ["text", "bindings"],
            },
        },
        "summary": {"type": "string", "maxLength": 400},
    },
    "required": ["verdict", "claims", "summary"],
}


class VerdictError(ValueError):
    pass


@dataclass
class Claim:
    text: str
    bindings: list[Binding]


@dataclass
class ModelVerdict:
    verdict: str
    summary: str
    claims: list[Claim]


@dataclass
class ClaimOutcome:
    claim: Claim
    admitted: bool
    reason: str = ""
    finding_id: str | None = None


@dataclass
class Decision:
    verdict: str
    model_verdict: str | None
    summary: str
    outcomes: list[ClaimOutcome] = field(default_factory=list)
    reason: str = ""

    @property
    def admitted(self) -> list[ClaimOutcome]:
        return [o for o in self.outcomes if o.admitted]

    @property
    def refused(self) -> list[ClaimOutcome]:
        return [o for o in self.outcomes if not o.admitted]


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.S)


def parse(text: str) -> ModelVerdict:
    """Read the model's answer. Anything off-schema is an error, never a repair."""
    try:
        doc: Any = json.loads(_FENCE.sub("", text.strip()))
    except json.JSONDecodeError as e:
        raise VerdictError(f"model output is not JSON: {e}") from e
    if not isinstance(doc, dict):
        raise VerdictError("model output is not a JSON object")
    verdict = doc.get("verdict")
    if verdict not in VERDICTS:
        raise VerdictError(f"verdict {verdict!r} is not one of {', '.join(VERDICTS)}")
    claims = []
    for i, item in enumerate(doc.get("claims") or []):
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            raise VerdictError(f"claim {i} has no text")
        bindings = []
        for b in item.get("bindings") or []:
            if not isinstance(b, dict) or not {"record_id", "field", "value"} <= set(b):
                raise VerdictError(f"claim {i} has a binding without record_id, field and value")
            bindings.append(Binding(str(b["record_id"]), str(b["field"]), b["value"]))
        claims.append(Claim(item["text"], bindings))
    return ModelVerdict(verdict, str(doc.get("summary") or ""), claims)


def decide(store: Store, answer: str, host: str, shown: dict[str, str] | None = None,
           may_dismiss: bool = True) -> Decision:
    """`shown` is every record the model saw, id -> kind; a benign verdict has to cite what happened.

    `may_dismiss` is False when the backend that answered is not trusted to close a finding;
    its benign verdict, however well supported, goes to a person.
    """
    try:
        model = parse(answer)
    except VerdictError as e:
        return Decision(NEEDS_HUMAN, None, "", reason=str(e))

    outcomes = []
    for claim in model.claims:
        verdict, finding_id = submit_finding(
            store, finding_type="observation", claim=claim.text, bindings=claim.bindings, host=host
        )
        outcomes.append(ClaimOutcome(claim, verdict.accepted, verdict.refutation, finding_id))

    decision = Decision(model.verdict, model.verdict, model.summary, outcomes)
    if not decision.admitted:
        decision.verdict = NEEDS_HUMAN
        decision.reason = "no claim was admitted, so nothing the model concluded rests on evidence"
    elif model.verdict == BENIGN and decision.refused:
        decision.verdict = NEEDS_HUMAN
        decision.reason = (
            f"benign, but {len(decision.refused)} of {len(outcomes)} claim(s) were refused;"
            " a dismissal built on a misread record goes to a human"
        )
    elif model.verdict == BENIGN and shown:
        happened = what_happened(shown)
        cited = {shown.get(b.record_id) for o in decision.admitted for b in o.claim.bindings}
        if not cited & happened:
            decision.verdict = NEEDS_HUMAN
            decision.reason = (
                f"benign, but no admitted claim cites the {' or '.join(sorted(happened))} record,"
                " which is what happened; a dismissal has to rest on it, not only on what was approved"
            )
    if decision.verdict == BENIGN and not may_dismiss:
        decision.verdict = NEEDS_HUMAN
        decision.reason = (
            "benign, from a model that may not dismiss findings (HUBTRIAGE_MAY_DISMISS);"
            " a person decides"
        )
    return decision


def what_happened(shown: dict[str, str]) -> set[str]:
    """The record kinds that show the activity: CloudTrail's answer if it was asked, else the finding."""
    return {kind for kind in shown.values() if kind.startswith("cloudtrail_event")} or {"finding"}
