variable "region" {
  description = <<-EOT
    The Region Security Lake is enabled in, and the Region these custom sources
    are created in. A custom source name is unique per Region, and the role
    Security Lake creates is named ...-{region}, so this is not a preference: it
    has to be the Region the connector writes to.
  EOT
  type        = string
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
    Name of the S3 bucket Security Lake created for this Region, typically
    aws-security-data-lake-{region}-{uid}. Used only to scope the Glue crawler
    role's read and write access; nothing here creates or configures the bucket.
  EOT
  type        = string
}

variable "provider_principal" {
  description = <<-EOT
    The AWS identity permitted to write these sources -- what the Security Lake
    console labels "AWS account with permission to write data". An account ID is
    what the console asks for. This is the identity the connector runs as, and it
    is what may assume the per-source AmazonSecurityLake-Provider-* role.
  EOT
  type        = string
}

variable "provider_external_id" {
  description = <<-EOT
    The external ID that identity must present. Pick an unguessable value and
    give the same one to the connector: it is what stops a third party who learns
    the role ARN from being able to assume it.
  EOT
  type        = string
  sensitive   = true
}
