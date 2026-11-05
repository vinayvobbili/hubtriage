# Stage 00: the management account.
#
# Runs with an IAM Identity Center session in the management account. It owns
# the things only the management account can own - the organization, its
# accounts, its policies, the budget - and hands the security services to the
# security account as delegated administrator, so that after this stage the
# management account is touched as little as possible.

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "hubtriage", ManagedBy = "terraform", Stage = "00-org" }
  }
}

# --------------------------------------------------------------- the budget
#
# First, because everything after it costs money. A budget alerts; it does not
# stop spend. Created in the management account it covers every account in the
# organization, since consolidated billing rolls them all up here.

resource "aws_budgets_budget" "monthly" {
  name         = "hubtriage-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = { actual_50 = ["ACTUAL", 50], actual_80 = ["ACTUAL", 80], actual_100 = ["ACTUAL", 100], forecast_100 = ["FORECASTED", 100] }
    content {
      comparison_operator        = "GREATER_THAN"
      notification_type          = notification.value[0]
      threshold                  = notification.value[1]
      threshold_type             = "PERCENTAGE"
      subscriber_email_addresses = [var.budget_email]
    }
  }
}

# --------------------------------------------------------- the organization
#
# Enabling IAM Identity Center creates the organization, so it already exists
# by the time this runs and is imported rather than created. The service
# principals are the complete list: anything enabled outside Terraform and left
# off it is disabled on apply, which for sso.amazonaws.com would cut off the
# session running the apply.

import {
  to = aws_organizations_organization.this
  id = var.organization_id
}

resource "aws_organizations_organization" "this" {
  feature_set = "ALL"
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "guardduty.amazonaws.com",
    "iam.amazonaws.com",
    "malware-protection.guardduty.amazonaws.com",
    "notifications.amazonaws.com", # AWS adds this one itself
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
  ]
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]
}

locals {
  root_id = aws_organizations_organization.this.roots[0].id
}

# Centralized root access: member accounts have no root password or keys at
# all, and the few tasks that need root are done from here with sts:AssumeRoot.
# New member accounts are created without root credentials.
resource "aws_iam_organizations_features" "root_access" {
  enabled_features = ["RootCredentialsManagement", "RootSessions"]
  depends_on       = [aws_organizations_organization.this]
}

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = local.root_id
}

# Every account needs its own email address. They come from tfvars, which is
# never committed.
resource "aws_organizations_account" "security" {
  name                       = "security"
  email                      = var.security_account_email
  parent_id                  = aws_organizations_organizational_unit.security.id
  role_name                  = "OrganizationAccountAccessRole"
  iam_user_access_to_billing = "DENY"
  close_on_deletion          = true
  depends_on                 = [aws_iam_organizations_features.root_access]

  lifecycle {
    # The API does not return role_name, so any change to it would read as drift.
    ignore_changes = [role_name]
  }
}

resource "aws_organizations_account" "workload" {
  name                       = "workload"
  email                      = var.workload_account_email
  parent_id                  = aws_organizations_organizational_unit.workloads.id
  role_name                  = "OrganizationAccountAccessRole"
  iam_user_access_to_billing = "DENY"
  close_on_deletion          = true
  depends_on                 = [aws_iam_organizations_features.root_access]

  lifecycle {
    ignore_changes = [role_name]
  }
}

# Your Identity Center login in the security account. The agent's role trusts
# Identity Center roles in that account only, so this is how it gets assumed.
# The user and the permission set are made by hand before the first apply.

data "aws_ssoadmin_instances" "this" {}

locals {
  sso_instance_arn  = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]
}

data "aws_ssoadmin_permission_set" "admin" {
  instance_arn = local.sso_instance_arn
  name         = "AdministratorAccess"
}

data "aws_identitystore_user" "you" {
  identity_store_id = local.identity_store_id
  alternate_identifier {
    unique_attribute {
      attribute_path  = "UserName"
      attribute_value = var.sso_user_name
    }
  }
}

resource "aws_ssoadmin_account_assignment" "security" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = data.aws_ssoadmin_permission_set.admin.arn
  principal_id       = data.aws_identitystore_user.you.user_id
  principal_type     = "USER"
  target_id          = aws_organizations_account.security.id
  target_type        = "AWS_ACCOUNT"
}

# ------------------------------------------------------ delegated administrators
#
# GuardDuty and Security Hub are regional, so delegation is per region; this
# project runs in one, and the region SCP below keeps everything else dark so
# there is no region where nobody is looking.
#
# One after another, not in parallel: each registers with Organizations, and
# concurrent registrations for one account fail with ConflictException.

resource "aws_guardduty_organization_admin_account" "security" {
  admin_account_id = aws_organizations_account.security.id
  depends_on       = [aws_organizations_organization.this]
}

# Security Hub must be on in the management account before it can delegate.
# Default standards off: they need AWS Config recording, which bills quietly.
# The delegation itself is in stage 10, after the security account's own hub.
resource "aws_securityhub_account" "management" {
  enable_default_standards = false
}

# Lets the security account create and own the organization trail.
resource "aws_cloudtrail_organization_delegated_admin_account" "security" {
  account_id = aws_organizations_account.security.id
  depends_on = [
    aws_organizations_organization.this,
    aws_guardduty_organization_admin_account.security,
  ]
}

# --------------------------------------------------------------------- SCPs
#
# SCPs never grant; they cap what IAM in member accounts can grant, root user
# included. They do not apply to the management account, which is one more
# reason to keep work out of it.

resource "aws_organizations_policy" "protect_security_services" {
  name        = "protect-security-services"
  description = "Members cannot leave, or switch off GuardDuty, Security Hub or the trail."
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/scp/protect-security-services.json")
}

resource "aws_organizations_policy" "region_allowlist" {
  name        = "region-allowlist"
  description = "Regional services only in the project region."
  type        = "SERVICE_CONTROL_POLICY"
  content     = templatefile("${path.module}/scp/region-allowlist.json.tftpl", { regions = [var.region] })
}

resource "aws_organizations_policy_attachment" "protect" {
  for_each  = { security = aws_organizations_organizational_unit.security.id, workloads = aws_organizations_organizational_unit.workloads.id }
  policy_id = aws_organizations_policy.protect_security_services.id
  target_id = each.value
}

resource "aws_organizations_policy_attachment" "regions" {
  for_each  = { security = aws_organizations_organizational_unit.security.id, workloads = aws_organizations_organizational_unit.workloads.id }
  policy_id = aws_organizations_policy.region_allowlist.id
  target_id = each.value
}
