"""Which AWS questions a finding raises, and how each answer becomes witness records.

The plan is deterministic and small on purpose. The model never chooses what to
look up: it is shown the answers to a fixed set of questions about the finding's
resources, and every claim it makes has to bind to one of those answers. A model
that can choose its own lookups can also choose not to make the one that would
contradict it.

The questions, by resource:

- An EC2 instance: ec2:DescribeInstances, then ec2:DescribeSecurityGroups for
  every group the instance is in - an "unprotected port is being probed" finding
  is only true if a group really lets the world reach that port.
- An IAM access key: iam:GetUser or iam:GetRole plus the attached managed
  policies, and cloudtrail:LookupEvents for that key around the finding's window.
  LookupEvents reads the account's 90-day management-event history, which exists
  whether or not anyone created a trail.
- The root user: cloudtrail:LookupEvents for `root` over the same window.

CloudTrail returns each event's body as a JSON *string* inside the response, so
as recorded none of its fields - who, from where, with which key - can be bound
to. The ingested copy has those strings decoded into objects. It is a derived
document and is recorded as one: its tool call names the raw recording's SHA-256
as its evidence, so the decode can be checked against what AWS actually sent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from witness.collectors import structured
from witness.store import Store, canonical, sha256_text

from .clients import Client, is_unavailable, to_json
from .findings import Finding

WINDOW = timedelta(hours=1)
CLOUDTRAIL_PAGE = 50


@dataclass(frozen=True)
class Lookup:
    service: str
    operation: str
    params: dict
    kind: str  # record kind in the store
    records_at: str | None = None  # where in the response the records sit
    decode_cloudtrail: bool = False

    @property
    def label(self) -> str:
        return f"{self.service}:{self.operation} {canonical(self.params)}"


@dataclass
class Collected:
    lookup: Lookup
    tool_call_id: str
    record_ids: list[str]
    kind: str
    error: str | None = None


@dataclass
class Evidence:
    finding_record_id: str
    collected: list[Collected] = field(default_factory=list)

    def kinds(self) -> dict[str, str]:
        """Every record the model was shown, by id, with its kind (the finding included)."""
        shown = {self.finding_record_id: "finding"}
        for c in self.collected:
            shown.update(dict.fromkeys(c.record_ids, c.kind))
        return shown


def _window(finding: Finding) -> dict:
    def parse(ts: str) -> datetime:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))

    start = parse(finding.created_at) - WINDOW
    end = parse(finding.updated_at or finding.created_at) + WINDOW
    return {"StartTime": start.isoformat(), "EndTime": end.isoformat()}


def _cloudtrail(attribute: str, value: str, finding: Finding) -> Lookup:
    return Lookup(
        "cloudtrail",
        "LookupEvents",
        {
            "LookupAttributes": [{"AttributeKey": attribute, "AttributeValue": value}],
            **_window(finding),
            "MaxResults": CLOUDTRAIL_PAGE,
        },
        kind="cloudtrail_event",
        records_at="Events",
        decode_cloudtrail=True,
    )


def plan(finding: Finding) -> list[Lookup]:
    lookups: list[Lookup] = []
    for instance_id in finding.instance_ids():
        lookups.append(
            Lookup(
                "ec2",
                "DescribeInstances",
                {"InstanceIds": [instance_id]},
                kind="ec2_instance",
                records_at="Reservations.0.Instances",
            )
        )
    for key in finding.access_keys():
        if key.principal_type == "Root":
            lookups.append(_cloudtrail("Username", "root", finding))
            continue
        if key.principal_type == "IAMUser" and key.principal_name:
            name = {"UserName": key.principal_name}
            lookups.append(Lookup("iam", "GetUser", name, kind="iam_user", records_at="User"))
            lookups.append(
                Lookup(
                    "iam",
                    "ListAttachedUserPolicies",
                    name,
                    kind="iam_attached_policy",
                    records_at="AttachedPolicies",
                )
            )
        elif key.principal_type == "AssumedRole" and key.principal_name:
            name = {"RoleName": key.principal_name}
            lookups.append(Lookup("iam", "GetRole", name, kind="iam_role", records_at="Role"))
            lookups.append(
                Lookup(
                    "iam",
                    "ListAttachedRolePolicies",
                    name,
                    kind="iam_attached_policy",
                    records_at="AttachedPolicies",
                )
            )
        if key.access_key_id:
            lookups.append(_cloudtrail("AccessKeyId", key.access_key_id, finding))
    return lookups


def follow_ups(lookup: Lookup, response: dict) -> list[Lookup]:
    """Questions only the first answer can raise."""
    if (lookup.service, lookup.operation) != ("ec2", "DescribeInstances"):
        return []
    group_ids = sorted(
        {
            group["GroupId"]
            for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
            for group in instance.get("SecurityGroups", [])
        }
    )
    if not group_ids:
        return []
    return [
        Lookup(
            "ec2",
            "DescribeSecurityGroups",
            {"GroupIds": group_ids},
            kind="ec2_security_group",
            records_at="SecurityGroups",
        )
    ]


def decode_cloudtrail(response: dict) -> dict:
    decoded = json.loads(json.dumps(response))
    for event in decoded.get("Events", []):
        body = event.get("CloudTrailEvent")
        if isinstance(body, str):
            event["CloudTrailEvent"] = json.loads(body)
    return decoded


def ingest_text(
    store: Store,
    *,
    tool: str,
    kind: str,
    text: str,
    records_at: str | None,
    host: str,
    evidence_path: str,
    evidence_sha256: str | None = None,
    mode: str = "replay",
) -> tuple[str, list[str], str]:
    """Land one response in the store, the way witness's own structured collector does.

    An answer with nothing at `records_at` - DescribeInstances for an instance
    that is gone, LookupEvents with no events - is not a failure. It is recorded
    whole, under `<kind>_empty`, because "AWS said there is nothing" is something a
    claim must be able to cite, and dropping it would make it indistinguishable
    from a question that was never asked.
    """
    try:
        parsed = structured.parse(text, records_at)
    except structured.ParseError:  # nothing at that path: no instance in the reservation
        parsed = None
    if parsed is None or not parsed.rows:  # or an empty list there: no events
        records_at, kind = None, f"{kind}_empty"
        parsed = structured.parse(text, None)
    tool_call_id = store.add_tool_call(
        tool=structured.TOOL_PREFIX + tool,
        argv=structured.argv_for(tool, kind, records_at or structured.ROOT, structured.JSON),
        mode=mode,
        output_text=text,
        host=host,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha256,
    )
    return tool_call_id, store.add_records(tool_call_id, kind, parsed.rows), kind


def ingest_finding(store: Store, finding: Finding) -> str:
    _, record_ids, _ = ingest_text(
        store,
        tool="securityhub.finding",
        kind="finding",
        text=to_json(finding.raw),
        records_at=None,
        host=finding.account_id,
        evidence_path=f"securityhub:GetFindings Id={finding.id}",
    )
    return record_ids[0]


def collect(store: Store, client: Client, finding: Finding, *, mode: str = "replay") -> Evidence:
    """Ask every question in the plan and land each answer as records.

    A lookup AWS refused - access denied, no such entity - or that was not recorded
    is kept as an error on the evidence rather than raised. The model is told which
    questions went unanswered, and the gate has nothing to bind to for them, which
    is the correct amount of weight for a missing answer.

    A lookup that never got an answer at all (see `is_unavailable`) stops the
    triage instead: no verdict is better than one built on a network failure.
    """
    evidence = Evidence(finding_record_id=ingest_finding(store, finding))
    queue = plan(finding)
    while queue:
        lookup = queue.pop(0)
        try:
            response = client.call(
                lookup.service,
                lookup.operation,
                lookup.params,
                account_id=finding.account_id,
                region=finding.region,
            )
        except Exception as e:  # noqa: BLE001 - every failure is reported
            if is_unavailable(e):
                raise
            evidence.collected.append(Collected(lookup, "", [], lookup.kind, error=str(e)))
            continue

        raw = to_json(response)
        text, raw_sha = raw, None
        if lookup.decode_cloudtrail:
            text, raw_sha = to_json(decode_cloudtrail(response)), sha256_text(raw)
        tool_call_id, record_ids, kind = ingest_text(
            store,
            tool=f"{lookup.service}.{lookup.operation}",
            kind=lookup.kind,
            text=text,
            records_at=lookup.records_at,
            host=finding.account_id,
            evidence_path=lookup.label,
            evidence_sha256=raw_sha,
            mode=mode,
        )
        evidence.collected.append(Collected(lookup, tool_call_id, record_ids, kind))
        queue.extend(follow_ups(lookup, response))
    return evidence
