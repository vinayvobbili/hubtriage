"""Reading new findings from Security Hub and writing verdicts back.

These run from the security account, which is the delegated administrator: it
sees every member account's findings, and BatchUpdateFindings from the
administrator can update any of them. A member account can only update its own.
"""

from __future__ import annotations

from typing import Any, Iterator

NEW_ACTIVE = {
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
}


def new_findings(securityhub: Any, product_name: str | None = "GuardDuty") -> Iterator[dict]:
    filters = dict(NEW_ACTIVE)
    if product_name:
        filters["ProductName"] = [{"Value": product_name, "Comparison": "EQUALS"}]
    for page in securityhub.get_paginator("get_findings").paginate(Filters=filters):
        yield from page["Findings"]


class WriteBackFailed(RuntimeError):
    pass


def write_back(securityhub: Any, update: dict) -> dict:
    """Send one update. A finding the hub would not take is an error, not a warning.

    BatchUpdateFindings returns 200 even when it changed nothing - per-finding
    failures come back in UnprocessedFindings - so success has to be read, not
    assumed from the absence of an exception.
    """
    response = securityhub.batch_update_findings(**update)
    if response.get("UnprocessedFindings"):
        raise WriteBackFailed(str(response["UnprocessedFindings"]))
    return response
