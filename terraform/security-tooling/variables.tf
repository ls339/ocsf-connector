variable "region" {
  description = "Region for the IAM calls. IAM is global; this only has to be a valid Region."
  type        = string
}

variable "account_id" {
  description = <<-EOT
    The security-tooling account: where the connector runs, and where the role it
    assumes lives. Not the log-archive account, and not the organization
    management account, which under AWS's Security Reference Architecture runs no
    workloads at all. Asserted against the credentials in use.
  EOT
  type        = string
}

variable "aws_profile" {
  description = "Named profile whose credentials reach that account. Null uses the default chain."
  type        = string
  default     = null
}

variable "role_name" {
  description = "Name of the role the connector runs as."
  type        = string
  default     = "ocsf-connector"
}

variable "trusted_principals" {
  description = <<-EOT
    Who may assume the connector's role. ARNs, not account ids.

    While the connector runs by hand this is the operator's own identity -- for
    AWS SSO, the full ARN of the permission set's role in this account, which
    carries a generated suffix and has to be read rather than guessed:
      aws sts get-caller-identity --query Arn
    When the connector moves to ECS, EKS or EC2, that compute's role joins this
    list and the human's can leave it. Nothing downstream changes, because the
    custom sources trust *this* role, not whoever assumed it.
  EOT
  type        = list(string)
}

variable "permissions_boundary" {
  description = <<-EOT
    ARN of a permissions boundary to attach to the connector's role.

    Many organisations require a boundary on every role created in their
    accounts, and refuse anything that creates one without. Without this option
    the module is simply unusable there, which is the kind of omission that gets
    an integration rejected at review rather than debated.
  EOT
  type        = string
  default     = null
}

variable "provider_role_arns" {
  description = <<-EOT
    The AmazonSecurityLake-Provider-* roles this connector may assume, from
    `terraform output provider_roles` in ../log-archive.

    Empty on the first apply, which is the point: this role has to exist before
    the custom sources can be registered to trust it, and the roles those
    sources create do not exist until they are. So the sequence is apply here,
    register there, apply here again with the ARNs. The policy is created only
    when this is non-empty, so phase one leaves nothing half-written.

    Listed exactly rather than matched with a wildcard: a wildcard would also
    trust a role somebody creates later with a matching name.
  EOT
  type        = list(string)
  default     = []
}
