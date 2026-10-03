variable "region" {
  description = <<-EOT
    The Region Security Lake is enabled in, and the Region these custom sources
    are created in. A custom source name is unique per Region, and the role
    Security Lake creates is named ...-{region}, so this is not a preference: it
    has to be the Region the connector writes to.
  EOT
  type        = string
}

variable "account_id" {
  description = <<-EOT
    The log-archive account: the Security Lake delegated administrator, which
    owns the data lake, its bucket, and the roles Security Lake creates per
    custom source. Asserted against the credentials in use, so this doubles as a
    guard against applying to the wrong account.
  EOT
  type        = string
}

variable "aws_profile" {
  description = "Named profile whose credentials reach that account. Null uses the default chain."
  type        = string
  default     = null
}

variable "source_name_prefix" {
  description = <<-EOT
    Prefixes every per-class custom source name: okta_authentication,
    okta_account_change, and so on. Must match sink.source_name in the
    connector's configuration exactly -- the name is in the S3 prefix the
    connector writes and in the Glue table a query binds to, so a mismatch means
    objects arriving where no registered source points.
  EOT
  type        = string
  default     = "okta"

  validation {
    # Security Lake allows 20 characters for a custom source name, so that the
    # AmazonSecurityLake-Provider-{name}-{region} role it creates stays under
    # IAM's 64. The longest suffix below is account_change at 14, plus the
    # separator, which leaves five. The connector enforces the same rule when its
    # configuration loads (docs/SPEC.md §4.1); this catches it before an apply.
    condition     = length(var.source_name_prefix) <= 5
    error_message = "At most 5 characters: 20 allowed, minus the 14-character longest class suffix and its underscore."
  }
}

variable "lake_bucket" {
  description = <<-EOT
    Name of the S3 bucket Security Lake created in this Region, typically
    aws-security-data-lake-{region}-{uid}. Used only to scope the Glue crawler
    role; nothing here creates or configures the bucket.
  EOT
  type        = string
}

variable "lake_kms_key_arn" {
  description = <<-EOT
    The customer-managed key encrypting the lake, if there is one. Security Lake
    attaches kms:Decrypt and kms:GenerateDataKey to the provider roles itself, so
    the write path needs nothing here -- but the Glue crawler role is ours, and a
    crawler that cannot decrypt reads nothing and populates no table. Null for an
    SSE-S3 lake.
  EOT
  type        = string
  default     = null
}

variable "provider_principal" {
  description = <<-EOT
    The identity permitted to write these sources: the ARN of the role the
    connector runs as, in the security-tooling account.

    A role ARN rather than an account id, deliberately. An account id trusts any
    principal in that account that also holds sts:AssumeRole, which is a much
    larger set than "the connector". There is no update-custom-log-source, and
    deleting a source leaves its Glue crawler behind, so this value is effectively
    permanent once applied.
  EOT
  type        = string
}

variable "provider_external_id" {
  description = <<-EOT
    The external id that identity must present. Pick an unguessable value and give
    the same one to the connector: it is what stops a third party who learns a
    role ARN from being able to assume it.
  EOT
  type        = string
  sensitive   = true
}
