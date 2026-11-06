# Stage 21: a lab that draws real GuardDuty findings, in the workload account.
#
# One small instance with SSH open to the internet. Scanners find an open 22 within
# hours, and GuardDuty reports what they do: Recon:EC2/PortProbeUnprotectedPort when a
# known-malicious host probes it, UnauthorizedAccess:EC2/SSHBruteForce when one keeps
# trying to log in. Those are the first findings hubtriage can triage that are not
# samples, with an instance that exists, a security group to read and a CloudTrail
# history (this stage's own RunInstances).
#
# Nobody can log in. There is no key pair, and Amazon Linux allows no password logins,
# so every attempt fails at sshd. No outbound rule either: if something did get in, it
# could not reach anything. No instance profile, so no credentials on the box.
#
# It costs money while it runs (an instance and a public IPv4 address, roughly a
# cent an hour together). Destroy it when there are enough findings:
#   terraform -chdir=21-lab-ssh destroy

data "terraform_remote_state" "org" {
  backend = "local"
  config  = { path = "${path.module}/../00-org/terraform.tfstate" }
}

provider "aws" {
  region = var.region
  assume_role {
    role_arn     = "arn:aws:iam::${data.terraform_remote_state.org.outputs.workload_account_id}:role/OrganizationAccountAccessRole"
    session_name = "terraform-21-lab-ssh"
  }
  default_tags {
    tags = { Project = "hubtriage", ManagedBy = "terraform", Stage = "21-lab-ssh" }
  }
}

# The default VPC every new account gets in each region: a public subnet per zone, already
# routed to an internet gateway. A lab this small does not need a network of its own.
data "aws_vpc" "default" {
  default = true
}

# AWS publishes the current Amazon Linux AMI id as a public SSM parameter, so the plan never
# pins an image that has gone stale.
data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_security_group" "ssh_open" {
  name        = "hubtriage-lab-ssh-open"
  description = "SSH from anywhere, to draw GuardDuty findings. No egress."
  vpc_id      = data.aws_vpc.default.id
  # No egress block: Terraform then removes the default allow-all egress rule.
}

resource "aws_vpc_security_group_ingress_rule" "ssh_from_anywhere" {
  security_group_id = aws_security_group.ssh_open.id
  description       = "SSH from the internet"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "target" {
  # A public AMI id is no secret; the plain value lets the plan show which image it is.
  ami                         = data.aws_ssm_parameter.al2023_arm64.insecure_value
  instance_type               = var.instance_type
  vpc_security_group_ids      = [aws_security_group.ssh_open.id]
  associate_public_ip_address = true

  metadata_options {
    http_tokens   = "required" # IMDSv2 only
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  tags = { Name = "hubtriage-lab-ssh" }
}
