variable "region" {
  description = "The one region this project runs in."
  type        = string
  default     = "us-east-1"
}

variable "organization_id" {
  description = "The organization IAM Identity Center created (o-...), imported on first apply."
  type        = string
}

variable "budget_email" {
  description = "Where budget alerts go."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget across the whole organization."
  type        = number
  default     = 20
}

variable "security_account_email" {
  description = "Root email for the security account. Must be unique across AWS."
  type        = string
}

variable "workload_account_email" {
  description = "Root email for the workload account. Must be unique across AWS."
  type        = string
}

variable "sso_user_name" {
  description = "Your IAM Identity Center username, given admin access to the security account."
  type        = string
}
