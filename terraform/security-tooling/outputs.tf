output "connector_role_arn" {
  description = <<-EOT
    What to pass as `provider_principal` when registering the custom sources in
    ../log-archive. A role ARN rather than this account's id, so that only the
    connector may write -- not everything in the account.
  EOT
  value       = aws_iam_role.connector.arn
}

output "can_assume_provider_roles" {
  description = "False until the second apply binds the ARNs registration produced."
  value       = length(var.provider_role_arns) > 0
}
