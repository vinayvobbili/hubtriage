"""Looking at the live setup, and poking it on purpose.

`status` reads the security account from its delegated-administrator seat. It only
reads, and it reads queue depth from the queue's attributes: receiving a message to
look at it would spend one of its three receives.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

QUEUE = "hubtriage-findings"
DEAD_LETTERS = "hubtriage-findings-dlq"
TOPIC = "hubtriage-alerts"
ALARM = "hubtriage-dead-letters"
SAMPLE_TYPES = [
    "Recon:EC2/PortProbeUnprotectedPort",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
]


@dataclass
class Line:
    name: str
    value: str
    ok: bool = True


def detector_id(guardduty: Any) -> str:
    return guardduty.list_detectors()["DetectorIds"][0]


def queue_depth(sqs: Any, name: str) -> tuple[int, int]:
    """(waiting, being handled). Reading attributes never counts as a receive."""
    url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    attributes = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return (
        int(attributes["ApproximateNumberOfMessages"]),
        int(attributes["ApproximateNumberOfMessagesNotVisible"]),
    )


def _topic_arn(sns: Any) -> str | None:
    for page in sns.get_paginator("list_topics").paginate():
        for topic in page["Topics"]:
            if topic["TopicArn"].endswith(f":{TOPIC}"):
                return topic["TopicArn"]
    return None


def status(session: Any, region: str) -> list[Line]:
    client = lambda name: session.client(name, region_name=region)  # noqa: E731
    hub, guardduty, sqs = client("securityhub"), client("guardduty"), client("sqs")
    lines = []

    standards = hub.get_enabled_standards()["StandardsSubscriptions"]
    lines.append(Line("standards enabled", str(len(standards)), not standards))

    members = hub.list_members(OnlyAssociated=False)["Members"]
    joined = ", ".join(f"{m['AccountId']} {m['MemberStatus']}" for m in members) or "none"
    lines.append(Line(
        "Security Hub members",
        joined,
        bool(members) and all(m["MemberStatus"] == "Enabled" for m in members),
    ))

    detector = detector_id(guardduty)
    members = guardduty.list_members(DetectorId=detector, OnlyAssociated="false")["Members"]
    joined = ", ".join(f"{m['AccountId']} {m['RelationshipStatus']}" for m in members) or "none"
    lines.append(Line(
        "GuardDuty members",
        joined,
        bool(members) and all(m["RelationshipStatus"] == "Enabled" for m in members),
    ))

    active = Counter()
    filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}
    for page in hub.get_paginator("get_findings").paginate(Filters=filters):
        active.update(f["ProductName"] for f in page["Findings"])
    lines.append(Line(
        "active findings", ", ".join(f"{n} {name}" for name, n in sorted(active.items())) or "none"
    ))

    waiting, handling = queue_depth(sqs, QUEUE)
    lines.append(Line("queue", f"{waiting} waiting, {handling} being handled"))
    parked, _ = queue_depth(sqs, DEAD_LETTERS)
    lines.append(Line("dead-letter queue", f"{parked} parked", parked == 0))

    topic = _topic_arn(client("sns"))
    subscriptions = (
        client("sns").list_subscriptions_by_topic(TopicArn=topic)["Subscriptions"] if topic else []
    )
    pending = [s for s in subscriptions if s["SubscriptionArn"] == "PendingConfirmation"]
    lines.append(Line(
        "alert emails",
        f"{len(subscriptions) - len(pending)} confirmed, {len(pending)} pending",
        bool(subscriptions) and not pending,
    ))

    alarms = client("cloudwatch").describe_alarms(AlarmNames=[ALARM])["MetricAlarms"]
    state = alarms[0]["StateValue"] if alarms else "missing"
    lines.append(Line("dead-letter alarm", state, state == "OK"))

    account = client("sts").get_caller_identity()["Account"]
    objects = client("s3").list_objects_v2(Bucket=f"hubtriage-trail-{account}", MaxKeys=1)
    delivered = objects.get("KeyCount", 0) > 0
    lines.append(Line("trail delivery", "delivering" if delivered else "nothing yet", delivered))
    return lines


def generate_samples(guardduty: Any, types: list[str] | None = None) -> None:
    guardduty.create_sample_findings(
        DetectorId=detector_id(guardduty), FindingTypes=types or SAMPLE_TYPES
    )


def wait_for_queue(
    sqs: Any,
    timeout: float,
    *,
    poll: float = 30.0,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """How many messages arrived, or 0 at the timeout. Parked messages count as a failure."""
    waited = 0.0
    while True:
        parked, _ = queue_depth(sqs, DEAD_LETTERS)
        if parked:
            raise RuntimeError(f"{parked} message(s) in the dead-letter queue")
        waiting, handling = queue_depth(sqs, QUEUE)
        if waiting + handling:
            return waiting + handling
        if waited >= timeout:
            return 0
        sleep(poll)
        waited += poll


def test_alert(cloudwatch: Any) -> None:
    """Sends one real email: alarm, topic, inbox. The alarm returns to OK on its next check."""
    cloudwatch.set_alarm_state(
        AlarmName=ALARM,
        StateValue="ALARM",
        StateReason="Test of the email path, forced by hubtriage test-alert.",
    )
