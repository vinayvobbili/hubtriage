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
You are triaging one AWS security finding. Decide whether it is a true positive,
benign, or needs a human, using only the records below.

Rules:
- Every claim must cite at least one binding: a record_id, a field name and a value,
  copied exactly as they appear in the records. Claims that do not match the record
  are refused, and refused claims count against your verdict.
- Say benign only if the records show why the activity is expected. Absence of
  evidence is not evidence of benign activity.
- If the records cannot settle it, say needs_human and cite what they do show.
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
