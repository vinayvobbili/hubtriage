"""A Security Hub finding, read as far as triage needs and no further.

Security Hub CSPM speaks ASFF, the AWS Security Finding Format: one JSON shape
that GuardDuty, Inspector, Macie, IAM Access Analyzer and partner products all
land in, which is why the agent reads findings from the hub rather than from
each product. The newer Security Hub speaks OCSF instead; that is a second
reader behind the same `Finding`, not a change to anything downstream.

Nothing here is interpreted. The raw document is kept whole, because it is
itself evidence - the agent's first record is the finding as the hub sent it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Resource:
    type: str
    id: str
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class AccessKey:
    """The principal a GuardDuty IAM finding is about."""

    access_key_id: str | None
    principal_name: str | None
    principal_type: str | None  # IAMUser, AssumedRole, Root, Federated...


@dataclass(frozen=True)
class Finding:
    id: str
    product_arn: str
    product_name: str
    account_id: str
    region: str
    types: tuple[str, ...]
    title: str
    severity: str
    created_at: str
    updated_at: str
    workflow_status: str
    resources: tuple[Resource, ...]
    raw: dict

    @classmethod
    def from_asff(cls, doc: dict) -> "Finding":
        missing = [k for k in ("Id", "ProductArn", "AwsAccountId") if not doc.get(k)]
        if missing:
            raise ValueError(f"not an ASFF finding: missing {', '.join(missing)}")
        return cls(
            id=doc["Id"],
            product_arn=doc["ProductArn"],
            product_name=doc.get("ProductName") or doc["ProductArn"].rsplit("/", 1)[-1],
            account_id=doc["AwsAccountId"],
            region=doc.get("Region") or _region_from_arn(doc["ProductArn"]),
            types=tuple(doc.get("Types") or ()),
            title=doc.get("Title", ""),
            severity=(doc.get("Severity") or {}).get("Label", "INFORMATIONAL"),
            created_at=doc.get("CreatedAt", ""),
            updated_at=doc.get("UpdatedAt", ""),
            workflow_status=(doc.get("Workflow") or {}).get("Status", "NEW"),
            resources=tuple(
                Resource(r.get("Type", ""), r.get("Id", ""), r.get("Details") or {})
                for r in doc.get("Resources") or ()
            ),
            raw=doc,
        )

    @classmethod
    def load(cls, path: str | Path) -> "Finding":
        return cls.from_asff(json.loads(Path(path).read_text(encoding="utf-8")))

    def instance_ids(self) -> list[str]:
        out = []
        for r in self.resources:
            if r.type == "AwsEc2Instance":
                out.append(r.id.rsplit("/", 1)[-1])
        return out

    def access_keys(self) -> list[AccessKey]:
        out = []
        for r in self.resources:
            if r.type != "AwsIamAccessKey":
                continue
            d = r.details.get("AwsIamAccessKey") or {}
            key_id = r.id.split(":")[-1] if r.id.startswith("AWS::IAM::AccessKey:") else None
            out.append(
                AccessKey(
                    access_key_id=key_id or d.get("AccessKeyId"),
                    principal_name=d.get("PrincipalName") or d.get("UserName"),
                    principal_type=d.get("PrincipalType"),
                )
            )
        return out


def _region_from_arn(arn: str) -> str:
    parts = arn.split(":")
    return parts[3] if len(parts) > 3 else ""
