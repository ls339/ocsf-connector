# The identity the connector runs as.
#
# It holds no permission to write the lake. Security Lake creates a role per
# custom source, scoped to that source's prefix, and this role's only privilege
# is permission to assume those (docs/SPEC.md §4.2). So the blast radius of a
# compromised connector is "can write Okta objects into seven prefixes", not
# "can write the security data lake".

resource "aws_iam_role" "connector" {
  name                 = var.role_name
  permissions_boundary = var.permissions_boundary
  description          = "Assumed by the Okta -> OCSF -> Security Lake connector; may assume the per-source provider roles and nothing else."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.trusted_principals }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Created only once registration has produced the role ARNs. Until then this
# role exists, is assumable, and can do nothing -- which is the correct state for
# a role whose purpose does not exist yet.
resource "aws_iam_role_policy" "assume_provider_roles" {
  count = length(var.provider_role_arns) > 0 ? 1 : 0

  name = "assume-security-lake-provider-roles"
  role = aws_iam_role.connector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssumeProviderRoles"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = var.provider_role_arns
    }]
  })
}
