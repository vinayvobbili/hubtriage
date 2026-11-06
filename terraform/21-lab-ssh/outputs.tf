output "instance_id" {
  description = "The id GuardDuty's findings will name."
  value       = aws_instance.target.id
}

output "public_ip" {
  value = aws_instance.target.public_ip
}
