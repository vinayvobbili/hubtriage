output "organization_id" {
  value = aws_organizations_organization.this.id
}

output "security_account_id" {
  value = aws_organizations_account.security.id
}

output "workload_account_id" {
  value = aws_organizations_account.workload.id
}

output "management_account_id" {
  value = aws_organizations_organization.this.master_account_id
}
