# The agent's role, and what it is not allowed to do.
#
# Assumed from your own Identity Center session in this account, so the agent
# runs with short-lived credentials and no access key exists anywhere. It can
# read findings, take them off the queue, write its verdict back, and assume the
# read-only enrichment role in any account in this organization. It cannot read
# a single resource itself, and it cannot close a finding.

data "aws_iam_policy_document" "agent_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:SetSourceIdentity"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.security_account}:root"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${local.security_account}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_*"]
    }
  }
}

locals {
  # Fields the product owns. The customer may write them with BatchUpdateFindings,
  # but the agent may not: its verdict goes in the note and the verification
  # state, never in a severity it would then be grading itself against.
  forbidden_fields = [
    "Confidence",
    "Criticality",
    "RelatedFindings",
    "Severity.Label",
    "Severity.Normalized",
    "Severity.Product",
    "Types",
  ]
}

data "aws_iam_policy_document" "agent" {
  statement {
    sid       = "ReadFindings"
    actions   = ["securityhub:GetFindings"]
    resources = ["*"]
  }

  statement {
    sid       = "WriteVerdicts"
    actions   = ["securityhub:BatchUpdateFindings"]
    resources = ["*"]
  }

  # A person closes findings. Denied in IAM, not merely absent from the code.
  statement {
    sid       = "NeverClose"
    effect    = "Deny"
    actions   = ["securityhub:BatchUpdateFindings"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "securityhub:ASFFSyntaxPath/Workflow.Status"
      values   = ["RESOLVED", "SUPPRESSED"]
    }
  }

  # One statement per field: keys inside a single Null condition are ANDed, so
  # listing them together would deny only a request that set all of them.
  dynamic "statement" {
    for_each = local.forbidden_fields
    content {
      sid       = "NotOwned${replace(statement.value, ".", "")}"
      effect    = "Deny"
      actions   = ["securityhub:BatchUpdateFindings"]
      resources = ["*"]
      condition {
        test     = "Null"
        variable = "securityhub:ASFFSyntaxPath/${statement.value}"
        values   = ["false"]
      }
    }
  }

  statement {
    sid = "TakeFromQueue"
    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
    ]
    resources = [aws_sqs_queue.findings.arn]
  }

  statement {
    sid       = "EnrichInsideTheOrganization"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/hubtriage-enrich"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceOrgID"
      values   = [local.org.organization_id]
    }
  }

  dynamic "statement" {
    for_each = length(var.bedrock_model_arns) > 0 ? [1] : []
    content {
      sid       = "OneModel"
      actions   = ["bedrock:InvokeModel"]
      resources = var.bedrock_model_arns
    }
  }
}

resource "aws_iam_role" "agent" {
  name                 = "hubtriage-agent"
  description          = "hubtriage: read findings, write verdicts, assume hubtriage-enrich"
  assume_role_policy   = data.aws_iam_policy_document.agent_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "agent" {
  name   = "hubtriage-agent"
  role   = aws_iam_role.agent.id
  policy = data.aws_iam_policy_document.agent.json
}

# Findings about the security account itself are enriched the same way as any
# other account's.
module "enrich" {
  source         = "../modules/enrich-role"
  agent_role_arn = aws_iam_role.agent.arn
}
