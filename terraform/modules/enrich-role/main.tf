# The only thing hubtriage can read, in any account: the questions in
# src/hubtriage/evidence.py and nothing else. Adding a lookup there means adding
# its action here, which is the point - the plan and the permission are reviewed
# together.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "agent_role_arn" {
  description = "The one principal allowed to assume this role."
  type        = string
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.agent_role_arn]
    }
  }
}

data "aws_iam_policy_document" "read" {
  statement {
    sid = "TheEvidencePlan"
    actions = [
      "cloudtrail:LookupEvents",
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "iam:GetRole",
      "iam:GetUser",
      "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "this" {
  name                 = "hubtriage-enrich"
  description          = "hubtriage read-only enrichment, assumed from the security account"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "read" {
  name   = "hubtriage-enrich"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.read.json
}

output "role_arn" {
  value = aws_iam_role.this.arn
}
