# One registered custom source per OCSF class (docs/SPEC.md §4.1), because
# Security Lake registers a Glue table per source and a single source spanning
# several classes would mix schemas in one table.
#
# The suffixes here must match the sink's naming table in
# src/ocsf_connector/sinks/naming.py exactly: the connector derives the source
# from the class it mapped, and writes to ext/{source}/..., so a suffix that
# disagrees means objects landing where no registered source points.
# tests/test_terraform_sources.py fails if the two drift apart.
#
# Three suffixes are shortened from OCSF's own class names -- session_authz,
# entity, group -- because AWS caps a source name at 20 characters and the OCSF
# names do not fit. §4.1 has the reasoning.
locals {
  # suffix => the OCSF event class AWS accepts for it, or null where AWS has none.
  #
  # base_event is the null. Unknown Okta event types degrade to OCSF Base Event
  # (CLAUDE.md invariant 4), and Base Event is absent from the list of event
  # classes a custom source may declare -- all six IAM classes are on it, nothing
  # resembling Base Event is. eventClasses is optional in the API, so this
  # registers the source without one and the first apply answers whether that is
  # accepted (ocsf-connector-pet.11.3). If it is refused, the source is not
  # registrable at all and degraded records stay in the bucket with no table
  # pointing at them, which loses nothing and is invisible to Athena.
  event_classes = {
    base_event     = null
    account_change = "ACCOUNT_CHANGE"
    authentication = "AUTHENTICATION"
    session_authz  = "AUTHORIZE_SESSION"
    entity         = "ENTITY_MANAGEMENT"
    user_access    = "USER_ACCESS"
    group          = "GROUP_MANAGEMENT"
  }
}

# Requires Security Lake to be enabled in var.region already. That is not managed
# here on purpose: enabling a data lake creates buckets, Lake Formation tables and
# crawlers, takes up to an hour, and in an Organization is the delegated
# administrator's decision rather than something a registration config should do
# as a side effect. If the lake does not exist, the API refuses these and says so.
resource "aws_securitylake_custom_log_source" "okta" {
  for_each = local.event_classes

  source_name = "${var.source_name_prefix}_${each.key}"

  # null omits the argument, which is what registering a source with no declared
  # event class means. A list with one entry is the ordinary case: one class per
  # source is the whole point of registering seven of them.
  event_classes = each.value == null ? null : [each.value]

  configuration {
    crawler_configuration {
      role_arn = aws_iam_role.crawler.arn
    }

    provider_identity {
      external_id = var.provider_external_id
      principal   = var.provider_principal
    }
  }

  # The crawler role must exist and carry its policies before Security Lake is
  # asked to pass it to a crawler; an attachment still in flight fails the create
  # with a permissions error that looks like a policy mistake.
  depends_on = [
    aws_iam_role_policy_attachment.crawler_service_role,
    aws_iam_role_policy.crawler_objects,
  ]
}
