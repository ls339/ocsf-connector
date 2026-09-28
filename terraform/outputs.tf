# What registration hands back, which is also what the connector needs to be told
# and what docs/SPEC.md §4.2 says to check rather than assume.

output "source_locations" {
  description = <<-EOT
    Source name => the S3 prefix Security Lake assigned it. Compare these against
    what the connector derives (ext/{source}/): a silent disagreement writes
    objects that no Glue table points at, which from the outside is
    indistinguishable from a stream with nothing to ship.
  EOT
  value = {
    for name, source in aws_securitylake_custom_log_source.okta :
    source.source_name => one(source.provider_details).location
  }
}

output "provider_roles" {
  description = <<-EOT
    Source name => the AmazonSecurityLake-Provider-* role that may write it. The
    connector assumes one of these per source, with the external ID it was
    configured with. Until it does, delivery uses the caller's own credentials
    and cannot write a registered source (§4.2).
  EOT
  value = {
    for name, source in aws_securitylake_custom_log_source.okta :
    source.source_name => one(source.provider_details).role_arn
  }
}

output "glue_tables" {
  description = "Source name => the Glue table a query binds to, for checking a crawler has run."
  value = {
    for name, source in aws_securitylake_custom_log_source.okta :
    source.source_name => one(source.attributes).table_arn
  }
}
