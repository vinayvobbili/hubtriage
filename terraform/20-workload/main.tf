# Stage 20: the workload account, where findings happen.
#
# For now it holds only the enrichment role. The resources that generate
# findings on purpose - a probe-able instance, a misused key - arrive one lab at
# a time, each with its own destroy.

data "terraform_remote_state" "org" {
  backend = "local"
  config  = { path = "${path.module}/../00-org/terraform.tfstate" }
}

data "terraform_remote_state" "security" {
  backend = "local"
  config  = { path = "${path.module}/../10-security/terraform.tfstate" }
}

provider "aws" {
  region = var.region
  assume_role {
    role_arn     = "arn:aws:iam::${data.terraform_remote_state.org.outputs.workload_account_id}:role/OrganizationAccountAccessRole"
    session_name = "terraform-20-workload"
  }
  default_tags {
    tags = { Project = "hubtriage", ManagedBy = "terraform", Stage = "20-workload" }
  }
}

module "enrich" {
  source         = "../modules/enrich-role"
  agent_role_arn = data.terraform_remote_state.security.outputs.agent_role_arn
}
