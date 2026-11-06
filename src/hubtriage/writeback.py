"""The verdict, as a BatchUpdateFindings request.

BatchUpdateFindings is the API for the *customer's* fields on a finding - the
workflow status, the note, the verification state, user-defined fields. The
fields the product owns (severity as GuardDuty set it, the types, the resources)
belong to BatchImportFindings and the product; the agent never touches them, and
the IAM policy in terraform/10-security says so too, with condition keys on the
field paths rather than trust in this module.

The agent never closes anything. Workflow goes to NOTIFIED - "someone has been
told" - and the verification state carries the verdict. RESOLVED and SUPPRESSED
are a person's call, and the same IAM policy denies them to the agent's role.
"""

from __future__ import annotations

from .findings import Finding
from .verdict import BENIGN, NEEDS_HUMAN, SAMPLE, TRUE_POSITIVE, Decision

NOTE_LIMIT = 512  # Note.Text maximum, in characters
UPDATED_BY = "hubtriage"

VERIFICATION_STATE = {
    TRUE_POSITIVE: "TRUE_POSITIVE",
    BENIGN: "BENIGN_POSITIVE",
    NEEDS_HUMAN: "UNKNOWN",
    SAMPLE: "FALSE_POSITIVE",  # GuardDuty made it up on request; nothing happened
}


def note_text(decision: Decision, ledger_head: str) -> str:
    """The note carries only what passed the gate.

    The model's summary is not in it. A summary is prose with no bindings, so it
    can say anything - and the first time this ran, the summary of a refused
    benign verdict repeated both refused claims into the finding's note.
    """
    head = (
        f"hubtriage: {decision.verdict}"
        f" ({len(decision.admitted)} claim(s) proved, {len(decision.refused)} refused)."
    )
    parts = [head]
    if decision.reason:
        parts.append(decision.reason)
    parts.extend(f"- {o.claim.text}" for o in decision.admitted)
    tail = f" [ledger {ledger_head[:16]}]"
    text = " ".join(parts)
    if len(text) + len(tail) > NOTE_LIMIT:
        text = text[: NOTE_LIMIT - len(tail) - 1].rstrip() + "…"
    return text + tail


def build_update(finding: Finding, decision: Decision, ledger_head: str) -> dict:
    return {
        "FindingIdentifiers": [{"Id": finding.id, "ProductArn": finding.product_arn}],
        "Note": {"Text": note_text(decision, ledger_head), "UpdatedBy": UPDATED_BY},
        "VerificationState": VERIFICATION_STATE[decision.verdict],
        "Workflow": {"Status": "NOTIFIED"},
        "UserDefinedFields": {
            "hubtriage_verdict": decision.verdict,
            "hubtriage_model_verdict": decision.model_verdict or "unparsed",
            "hubtriage_claims_refused": str(len(decision.refused)),
            "hubtriage_ledger": ledger_head,
        },
    }
