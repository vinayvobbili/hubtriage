"""Reading new findings from Security Hub and writing verdicts back.

These run from the security account, which is the delegated administrator: it
sees every member account's findings, and BatchUpdateFindings from the
administrator can update any of them. A member account can only update its own.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Iterator

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


class NotInHub(LookupError):
    pass


# The import event can arrive before GetFindings can return the finding: on the
# first real run a finding was still missing 54 seconds after its event. Waiting
# here beats leaving the message for the queue to redeliver, which costs one of its
# three receives and a full visibility timeout.
READ_ATTEMPTS = 12
READ_WAIT_SECONDS = 15


def read(
    securityhub: Any,
    finding_id: str,
    product_arn: str | None = None,
    *,
    attempts: int = READ_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """One finding as the hub has it now, allowing for the delay after its import."""
    filters = {"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]}
    if product_arn:
        filters["ProductArn"] = [{"Value": product_arn, "Comparison": "EQUALS"}]
    for attempt in range(attempts):
        found = securityhub.get_findings(Filters=filters, MaxResults=1)["Findings"]
        if found:
            return found[0]
        if attempt + 1 < attempts:
            sleep(READ_WAIT_SECONDS)
    raise NotInHub(finding_id)


def still_new(
    securityhub: Any,
    finding_id: str,
    product_arn: str,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> dict | None:
    """The finding as the hub has it now, or None once it is no longer waiting for triage.

    A queued event is a copy from when it was sent. By the time it is read, the
    agent may already have answered (SQS can deliver a message twice) or a person
    may have closed the finding, and neither should be overwritten.
    """
    doc = read(securityhub, finding_id, product_arn, sleep=sleep)
    waiting = doc.get("Workflow", {}).get("Status") == "NEW" and doc.get("RecordState") == "ACTIVE"
    return doc if waiting else None


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
