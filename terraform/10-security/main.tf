# Stage 10: the security account, the hub.
#
# Runs from the management account's Identity Center session, assuming the
# OrganizationAccountAccessRole that Organizations created in the security
# account. Everything the organization's security depends on is configured
# here: GuardDuty and Security Hub as delegated administrator for every member,
# the organization trail, the event path that carries new findings to the
# agent, and the agent's own role.

data "terraform_remote_state" "org" {
  backend = "local"
  config  = { path = "${path.module}/../00-org/terraform.tfstate" }
}

locals {
  org              = data.terraform_remote_state.org.outputs
  security_account = local.org.security_account_id
  trail_name       = "hubtriage-org"
  # An organization trail belongs to the management account whichever account
  # created it, so that is the account in its ARN and in the log prefix.
  trail_arn = "arn:aws:cloudtrail:${var.region}:${local.org.management_account_id}:trail/${local.trail_name}"
}

provider "aws" {
  region = var.region
  assume_role {
    role_arn     = "arn:aws:iam::${local.security_account}:role/OrganizationAccountAccessRole"
    session_name = "terraform-10-security"
  }
  default_tags {
    tags = { Project = "hubtriage", ManagedBy = "terraform", Stage = "10-security" }
  }
}

# The session itself, without the assume_role: the management account.
provider "aws" {
  alias  = "management"
  region = var.region
  default_tags {
    tags = { Project = "hubtriage", ManagedBy = "terraform", Stage = "10-security" }
  }
}

# ---------------------------------------------------------------- GuardDuty
#
# Designating the delegated administrator turned GuardDuty on here, so the
# detector already exists and is read, not created. ALL enrolls every current
# and future member. The paid protection plans stay off; the foundational
# sources - CloudTrail management events, VPC flow logs, DNS logs - are what
# the findings in this project come from, and they need no configuration.

data "aws_guardduty_detector" "this" {}

resource "aws_guardduty_organization_configuration" "this" {
  detector_id                      = data.aws_guardduty_detector.this.id
  auto_enable_organization_members = "ALL"
}

locals {
  paid_protection_plans = [
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "RUNTIME_MONITORING",
    "LAMBDA_NETWORK_LOGS",
  ]
}

resource "aws_guardduty_organization_configuration_feature" "off" {
  for_each    = toset(local.paid_protection_plans)
  detector_id = data.aws_guardduty_detector.this.id
  name        = each.value
  auto_enable = "NONE"
  # AWS adds sub-settings to some plans (off, like their parent); left to it.
  lifecycle {
    ignore_changes = [additional_configuration]
  }
}

resource "aws_guardduty_detector_feature" "off" {
  for_each    = toset(local.paid_protection_plans)
  detector_id = data.aws_guardduty_detector.this.id
  name        = each.value
  status      = "DISABLED"
  lifecycle {
    ignore_changes = [additional_configuration]
  }
}

# ALL skips the management account: GuardDuty must already be on there before
# the delegated administrator can add it, and nothing turns it on. Without this
# the account that owns the organization - and its root user - is watched by
# nobody. Its paid plans go off before it joins, like everyone else's.
resource "aws_guardduty_detector" "management" {
  provider = aws.management
  enable   = true
}

resource "aws_guardduty_detector_feature" "management_off" {
  provider    = aws.management
  for_each    = toset(local.paid_protection_plans)
  detector_id = aws_guardduty_detector.management.id
  name        = each.value
  status      = "DISABLED"
  lifecycle {
    ignore_changes = [additional_configuration]
  }
}

data "aws_organizations_organization" "this" {
  provider = aws.management
}

resource "aws_guardduty_member" "management" {
  account_id  = local.org.management_account_id
  detector_id = data.aws_guardduty_detector.this.id
  email       = data.aws_organizations_organization.this.master_account_email
  depends_on  = [aws_guardduty_detector_feature.management_off]
  # An organization account is associated, not invited; nothing to accept.
  lifecycle {
    ignore_changes = [invite, email]
  }
}

# ------------------------------------------------------------- Security Hub
#
# LOCAL configuration: no standard is switched on, because every CSPM control
# evaluates through AWS Config and Config bills per recorded item. GuardDuty
# findings flow in regardless.
#
# The order matters. Delegating to an account whose hub is off switches the hub
# on with the default standards, so the hub comes first, without them.

resource "aws_securityhub_account" "security" {
  enable_default_standards = false
}

resource "aws_securityhub_organization_admin_account" "security" {
  provider         = aws.management
  admin_account_id = local.security_account
  depends_on       = [aws_securityhub_account.security]
}

resource "aws_securityhub_organization_configuration" "this" {
  auto_enable           = true
  auto_enable_standards = "NONE"
  organization_configuration {
    configuration_type = "LOCAL"
  }
  depends_on = [aws_securityhub_organization_admin_account.security]
}

# auto_enable covers accounts that join later. These two already exist.
resource "aws_securityhub_member" "existing" {
  for_each = {
    management = local.org.management_account_id
    workload   = local.org.workload_account_id
  }
  account_id = each.value
  invite     = false
  depends_on = [aws_securityhub_organization_configuration.this]
}

# ------------------------------------------------------- organization trail
#
# GuardDuty reads CloudTrail management events on its own, trail or no trail,
# and LookupEvents reads 90 days of event history the same way. The trail is
# for what outlives that: a durable, integrity-checked copy of every account's
# management events, in a bucket no member account can write to or delete from.

resource "aws_s3_bucket" "trail" {
  bucket = "hubtriage-trail-${local.security_account}"
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.trail_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    # Confused-deputy guard: only this trail, not any trail anyone points here.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
  statement {
    sid     = "CloudTrailWrite"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.trail.arn}/AWSLogs/${local.org.management_account_id}/*",
      "${aws_s3_bucket.trail.arn}/AWSLogs/${local.org.organization_id}/*",
    ]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
  statement {
    sid       = "TlsOnly"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

# Managed from the management account, which owns the trail. A delegated
# administrator can create it, but DescribeTrails from there refuses the trail's
# own ARN ("Account number does not match caller's account"), so the provider
# could not read back what it had just made.
resource "aws_cloudtrail" "org" {
  provider                      = aws.management
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  # Hourly signed digest files: `aws cloudtrail validate-logs` proves no log
  # file was changed or removed after delivery.
  enable_log_file_validation = true
  depends_on                 = [aws_s3_bucket_policy.trail]
}

# ------------------------------------------------- new findings, as a queue
#
# The delegated administrator receives an EventBridge event for every finding
# Security Hub imports, from every member. A queue between the event and the
# agent means a laptop that is asleep loses nothing, a finding the agent chokes
# on is retried and then parked in the dead-letter queue, and the agent pulls
# at its own pace.

resource "aws_sqs_queue" "dlq" {
  name                      = "hubtriage-findings-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "findings" {
  name                       = "hubtriage-findings"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 345600
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_cloudwatch_event_rule" "new_findings" {
  name        = "hubtriage-new-findings"
  description = "New, active GuardDuty findings imported into Security Hub."
  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        ProductName = ["GuardDuty"]
        RecordState = ["ACTIVE"]
        Workflow    = { Status = ["NEW"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "queue" {
  rule = aws_cloudwatch_event_rule.new_findings.name
  arn  = aws_sqs_queue.findings.arn
}

data "aws_iam_policy_document" "queue" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.findings.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.new_findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "findings" {
  queue_url = aws_sqs_queue.findings.id
  policy    = data.aws_iam_policy_document.queue.json
}
