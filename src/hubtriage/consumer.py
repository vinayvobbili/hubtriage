"""Taking findings off the queue, one message at a time.

EventBridge puts each "Security Hub Findings - Imported" event on an SQS queue,
which has a dead-letter queue behind it. SQS has no "failed" call: a message that
is received and not deleted comes back when its visibility timeout ends, and
after three receives SQS moves it to the dead-letter queue. So the whole error
policy here is one rule, which is to delete a message only once its findings have
been answered. Anything that goes wrong leaves it on the queue.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from . import hub
from .clients import is_unavailable
from .findings import Finding
from .triage import Result

# Long enough for a slow local model and a failover to the next host. The queue's
# own default is shorter, and a message that came back mid-triage would be triaged
# twice at once.
VISIBILITY_SECONDS = 900
WAIT_SECONDS = 20


class BadMessage(ValueError):
    pass


def findings_in(body: str) -> list[dict]:
    try:
        event = json.loads(body)
        findings = event["detail"]["findings"]
    except (ValueError, KeyError, TypeError) as e:
        raise BadMessage(f"not a Security Hub event: {e}") from e
    if not isinstance(findings, list) or not findings:
        raise BadMessage("event carries no findings")
    return findings


@dataclass
class Tally:
    messages: int = 0
    failed: int = 0


def drain(
    sqs: Any,
    queue_url: str,
    handle: Callable[[dict], None],
    *,
    delete: bool = True,
    follow: bool = False,
    log: Callable[[str], None] = print,
) -> Tally:
    """Handle messages until the queue is empty, or for as long as it runs with `follow`.

    A failure in one message is logged and the next one still runs. A failure that
    is not about the message (see `is_unavailable`) stops the run: no network or an
    expired login should not use up every message's three receives.
    """
    tally = Tally()
    while True:
        messages = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=WAIT_SECONDS,
            VisibilityTimeout=VISIBILITY_SECONDS,
        ).get("Messages", [])
        if not messages:
            if follow:
                continue
            return tally
        message = messages[0]
        tally.messages += 1
        try:
            for raw in findings_in(message["Body"]):
                handle(raw)
        except Exception as e:  # noqa: BLE001 - whatever it was, SQS retries, then parks it
            if is_unavailable(e):
                raise
            tally.failed += 1
            log(f"left on the queue: {type(e).__name__}: {e}")
            continue
        if delete:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])


def triage_new(
    securityhub: Any,
    raw: dict,
    run: Callable[[dict], Result],
    *,
    write_back: bool = True,
    product: str | None = "GuardDuty",
    answered: set[str] | None = None,
    log: Callable[[str], None] = print,
) -> Result | None:
    """Triage one finding from an event if it still needs it. None means nothing to do.

    `answered` holds the findings this run has written back. The hub can go on
    returning a finding as NEW for a minute or more after that write, so its own
    answer is not enough to catch a second delivery.
    """
    finding = Finding.from_asff(raw)
    # The event rule matches if any finding in the event does, so each is checked.
    if product and raw.get("ProductName") != product:
        log(f"skipped, not {product}: {finding.title}")
        return None
    if answered is not None and finding.id in answered:
        log(f"skipped, answered in this run: {finding.title}")
        return None
    current = hub.still_new(securityhub, finding.id, finding.product_arn)
    if current is None:
        log(f"skipped, already handled: {finding.title}")
        return None
    result = run(current)
    if write_back:
        hub.write_back(securityhub, result.update)
        if answered is not None:
            answered.add(finding.id)
    return result
