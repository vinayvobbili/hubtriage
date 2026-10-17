output "agent_role_arn" {
  value = aws_iam_role.agent.arn
}

output "findings_queue_url" {
  value = aws_sqs_queue.findings.id
}

output "trail_bucket" {
  value = aws_s3_bucket.trail.id
}
