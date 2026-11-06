variable "region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  description = "The smallest Graviton size; the instance only has to answer on port 22."
  type        = string
  default     = "t4g.nano"
}
