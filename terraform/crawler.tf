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

resource "aws_iam_role" "crawler" {
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
  role       = aws_iam_role.crawler.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "crawler_objects" {
  name = "lake-objects"
  role = aws_iam_role.crawler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "S3WriteRead"
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
      ]
      Resource = ["arn:aws:s3:::${var.lake_bucket}/*"]
    }]
  })
}
