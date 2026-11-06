"""The one prompt the model sees: the records, and the rules for citing them.

The model gets records, never raw responses. Each record is shown with its id
and its flattened fields, which are exactly the names and values the gate will
compare against - so a correct citation is a copy, not a reconstruction.
"""

from __future__ import annotations

import json

from witness.store import Store

from .evidence import Evidence
from .findings import Finding
from .verdict import SCHEMA

INSTRUCTIONS = """\
You are triaging one AWS security finding, using only the records below. The
finding itself is the first record: it is what GuardDuty saw. The rest are what
AWS answered when asked about the resources it names. Pick one verdict:

- true_positive: the records confirm what the finding describes - the activity
  happened, or the exposure exists - and nothing in them says it was approved.
  This is the default for a confirmed risk: not knowing whether someone approved
  it is not a reason for needs_human, since escalating is how a person gets asked.
- benign: the records confirm the activity, and they also show it was expected:
  a tag, a description or a trust policy that says this principal or resource is
  meant to do exactly this. Anything the records show going beyond that stated
  purpose makes it a true_positive instead.
- needs_human: the records cannot confirm what the finding describes. A lookup
  failed or came back empty, or the records contradict the finding.

Rules:
- Every claim must cite at least one binding: a record_id, a field name and a value,
  copied exactly as they appear in the records. A value keeps its JSON type: a field
  shown as true or 3 is cited as true or 3, one shown as "false" as "false". Claims
  that do not match the record are refused, and refused claims count against your verdict.
- Cite the records the verdict turns on: for benign, the one that shows the activity
  was expected; for needs_human, what is missing or contradicts the finding.
- Answer with one JSON object and nothing else, in this shape:
"""


def build(store: Store, finding: Finding, evidence: Evidence) -> str:
    sections = [INSTRUCTIONS + json.dumps(SCHEMA, indent=2), ""]
    sections.append(f"Finding: {finding.title} ({finding.severity}) in account {finding.account_id}")
    sections.append("")
    sections.append("Records:")
    for record in store.query_records(host=finding.account_id):
        sections.append(f"\n[{record['record_id']}] kind={record['kind']}")
        for name, value in record["fields"].items():
            sections.append(f"  {name} = {json.dumps(value)}")
    unanswered = [c for c in evidence.collected if c.error]
    if unanswered:
        sections.append("\nLookups that failed (nothing can be cited from these):")
        for c in unanswered:
            sections.append(f"  {c.lookup.label}: {c.error}")
    return "\n".join(sections) + "\n"
