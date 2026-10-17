variable "region" {
  type    = string
  default = "us-east-1"
}

variable "trail_retention_days" {
  description = "How long organization trail logs are kept."
  type        = number
  default     = 90
}

variable "bedrock_model_arns" {
  description = "Bedrock model (and inference profile) ARNs the agent may invoke. Empty: none."
  type        = list(string)
  default     = []
}
