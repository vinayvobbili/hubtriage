"""Proving the agent's IAM limits against real AWS.

The deny statements in terraform/10-security/agent.tf are conditions on the fields
of a request, and nothing offline evaluates those. This sends each forbidden write
for real, as the agent. A rule that does not hold therefore changes the finding, so
it runs only on a finding GuardDuty generated as a sample.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .clients import is_unavailable

# GuardDuty fills a sample's threat and network details with values like
# GeneratedFindingThreatName. Its own API also has a sample flag; the copy in
# Security Hub does not.
SAMPLE_MARK = "GeneratedFinding"

CLOSING = {"Workflow.Status=RESOLVED", "Workflow.Status=SUPPRESSED"}
DENIED_CODES = {"AccessDenied", "AccessDeniedException"}


class NotASample(ValueError):
    pass


def is_sample(raw: dict) -> bool:
    return SAMPLE_MARK in json.dumps(raw)


def forbidden_writes(raw: dict) -> dict[str, dict]:
    """Every write the agent must be refused, by the field the IAM rule names."""
    return {
        "Workflow.Status=RESOLVED": {"Workflow": {"Status": "RESOLVED"}},
        "Workflow.Status=SUPPRESSED": {"Workflow": {"Status": "SUPPRESSED"}},
        "Confidence": {"Confidence": 1},
        "Criticality": {"Criticality": 1},
        "RelatedFindings": {"RelatedFindings": [{"ProductArn": raw["ProductArn"], "Id": raw["Id"]}]},
        "Severity.Label": {"Severity": {"Label": "INFORMATIONAL"}},
        "Severity.Normalized": {"Severity": {"Normalized": 1}},
        "Severity.Product": {"Severity": {"Product": 1.0}},
        "Types": {"Types": ["Software and Configuration Checks/Test"]},
    }


# Without a write that succeeds, every refusal could just mean the role has no access at all.
CONTROL = {"Note": {"Text": "hubtriage check-iam: notes are allowed", "UpdatedBy": "hubtriage-check-iam"}}


@dataclass
class Probe:
    name: str
    expected: str
    got: str

    @property
    def ok(self) -> bool:
        return self.got == self.expected


def _attempt(securityhub: Any, identifier: dict, change: dict) -> str:
    try:
        response = securityhub.batch_update_findings(FindingIdentifiers=[identifier], **change)
    except Exception as e:  # noqa: BLE001 - anything but a refusal is reported as what it was
        if is_unavailable(e):
            raise
        code = getattr(e, "response", {}).get("Error", {}).get("Code")
        return "denied" if code in DENIED_CODES else (code or type(e).__name__)
    return "unprocessed" if response.get("UnprocessedFindings") else "allowed"


def check(securityhub: Any, raw: dict) -> list[Probe]:
    """Try each forbidden write, then the allowed one. Refuses anything but a sample."""
    if not is_sample(raw):
        raise NotASample(f"not a GuardDuty sample, so not safe to test on: {raw.get('Id')}")
    identifier = {"Id": raw["Id"], "ProductArn": raw["ProductArn"]}
    probes = [
        Probe(name, "denied", _attempt(securityhub, identifier, change))
        for name, change in forbidden_writes(raw).items()
    ]
    probes.append(Probe("Note", "allowed", _attempt(securityhub, identifier, CONTROL)))
    return probes
