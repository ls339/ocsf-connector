# The Glue crawler role, which registration requires to exist first.
#
# Only the API and CLI path needs this; the console creates an equivalent role on
# your behalf. AWS's own page shows a managed policy, an inline policy over the
# lake bucket, and a trust policy -- and its prose describes that trust policy as
# permitting "an AWS account ... based on the external ID" while the JSON beneath
# it trusts glue.amazonaws.com. The JSON is the one that matches what the role is
# for: a crawler reads objects, it does not assume anything on a provider's
# behalf. The external-id trust belongs to the provider role Security Lake
# creates per source, which is not managed here because Security Lake owns it.

locals {
  # Theirs if supplied, ours otherwise. Everything downstream reads this, so the
  # choice is invisible past this line.
  crawler_role_arn = var.crawler_role_arn != null ? var.crawler_role_arn : one(aws_iam_role.crawler[*].arn)
}

resource "aws_iam_role" "crawler" {
  count = var.crawler_role_arn == null ? 1 : 0

  name        = "${var.source_name_prefix}-securitylake-crawler-${var.region}"
  description = "Lets the Glue crawler read ${var.source_name_prefix}_* custom source objects and keep their tables current."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "glue.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "crawler_service_role" {
  count = var.crawler_role_arn == null ? 1 : 0

  role       = aws_iam_role.crawler[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "crawler_objects" {
  count = var.crawler_role_arn == null ? 1 : 0

  name = "lake-objects"
  role = aws_iam_role.crawler[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid    = "S3WriteRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
        ]
        Resource = ["arn:aws:s3:::${var.lake_bucket}/*"]
      }],
      # Under a customer-managed key the crawler cannot read the objects it is
      # meant to describe, and the failure is quiet: the crawler runs, finds
      # nothing it can decrypt, and leaves the table empty. Security Lake grants
      # the *provider* roles their KMS permissions itself; this role is ours.
      # The encryption-context condition is the shape AWS's own example uses.
      var.lake_kms_key_arn == null ? [] : [{
        Sid    = "LakeKey"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = [var.lake_kms_key_arn]
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:s3:arn" = "arn:aws:s3:::${var.lake_bucket}"
          }
        }
      }],
    )
  })
}
