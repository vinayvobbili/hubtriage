"""A health check for the stage-21 lab: is the instance up, and is GuardDuty seeing it?

Two accounts, two sessions: EC2 in the workload account, GuardDuty from the security
account's delegated-administrator seat. Everything here only reads.
"""

from __future__ import annotations

from typing import Any

from .live import Line, detector_id

# GetUsageStatistics wants the data sources named, and rejects any it does not list.
DATA_SOURCES = [
    "FLOW_LOGS", "CLOUD_TRAIL", "DNS_LOGS", "S3_LOGS", "KUBERNETES_AUDIT_LOGS", "EC2_MALWARE_SCAN",
]


def open_ingress(workload: Any, group_ids: list[str]) -> list[str]:
    """Each ingress rule of these groups that is open to the whole internet, like 'tcp 22'."""
    if not group_ids:
        return []
    out = []
    for group in workload.describe_security_groups(GroupIds=group_ids)["SecurityGroups"]:
        for rule in group["IpPermissions"]:
            if not any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])):
                continue
            protocol = "all" if rule["IpProtocol"] == "-1" else rule["IpProtocol"]
            low, high = rule.get("FromPort"), rule.get("ToPort")
            ports = "" if low is None else f" {low}" if low == high else f" {low}-{high}"
            out.append(f"{group['GroupId']} {protocol}{ports}")
    return out


def instance_lines(workload: Any, instance: str) -> list[Line]:
    reservations = workload.describe_instances(InstanceIds=[instance])["Reservations"]
    found = [i for r in reservations for i in r["Instances"]]
    if not found:
        return [Line("instance", f"{instance} not found", False)]
    box = found[0]
    state = box["State"]["Name"]
    groups = [g["GroupId"] for g in box.get("SecurityGroups", [])]
    return [
        Line("instance state", state, state == "running"),
        Line("launched", box["LaunchTime"].isoformat()),
        Line("public IP", box.get("PublicIpAddress") or "none"),
        Line("open to 0.0.0.0/0", ", ".join(open_ingress(workload, groups)) or "nothing"),
    ]


def is_sample(finding: dict) -> bool:
    """GuardDuty marks a sample in Service.AdditionalInfo.Sample (a bool, or 'true' as text)."""
    sample = (finding.get("Service") or {}).get("AdditionalInfo", {}).get("Sample", False)
    return str(sample).lower() == "true"


def finding_lines(guardduty: Any, detector: str, instance: str) -> list[Line]:
    criteria = {"Criterion": {
        "resource.instanceDetails.instanceId": {"Eq": [instance]},
        "service.archived": {"Eq": ["false"]},
    }}
    ids: list[str] = []
    for page in guardduty.get_paginator("list_findings").paginate(
        DetectorId=detector, FindingCriteria=criteria
    ):
        ids.extend(page["FindingIds"])
    findings = []
    # GetFindings takes at most 50 ids.
    for start in range(0, len(ids), 50):
        got = guardduty.get_findings(DetectorId=detector, FindingIds=ids[start:start + 50])
        findings.extend(f for f in got["Findings"] if not is_sample(f))
    if not findings:
        return [Line("findings", "none for this instance")]
    lines = [Line("findings", str(len(findings)))]
    for f in sorted(findings, key=lambda f: f["Service"]["EventLastSeen"]):
        service = f["Service"]
        lines.append(Line(
            f["Type"],
            f"severity {f['Severity']}, seen {service.get('Count', 1)}x,"
            f" first {service['EventFirstSeen']}, last {service['EventLastSeen']}",
        ))
    return lines


def detector_lines(guardduty: Any, detector: str) -> list[Line]:
    frequency = guardduty.get_detector(DetectorId=detector)["FindingPublishingFrequency"]
    members = guardduty.list_members(DetectorId=detector, OnlyAssociated="false")["Members"]
    joined = ", ".join(f"{m['AccountId']} {m['RelationshipStatus']}" for m in members) or "none"
    return [Line("publishing frequency", frequency), Line("GuardDuty members", joined)]


def usage_lines(guardduty: Any, detector: str) -> list[Line]:
    stats = guardduty.get_usage_statistics(
        DetectorId=detector,
        UsageStatisticType="SUM_BY_DATA_SOURCE",
        UsageCriteria={"DataSources": DATA_SOURCES},
    )["UsageStatistics"]["SumByDataSource"]
    seen = {s["DataSource"]: s["Total"] for s in stats}
    lines = []
    for source in DATA_SOURCES:
        total = seen.get(source)
        value = f"{total['Amount']} {total.get('Unit', '')}".strip() if total else "no usage"
        lines.append(Line(f"usage {source}", value))
    return lines


def lab(security: Any, workload: Any, instance: str) -> list[Line]:
    """`security` and `workload` are sessions' clients for guardduty and ec2 respectively."""
    detector = detector_id(security)
    return (
        instance_lines(workload, instance)
        + finding_lines(security, detector, instance)
        + detector_lines(security, detector)
        + usage_lines(security, detector)
    )
