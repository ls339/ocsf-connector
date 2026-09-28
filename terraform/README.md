# Registering the Security Lake custom sources

One custom source per OCSF class, the Glue crawler role the API path requires,
and the outputs that tell the connector where to write. Seven sources, well
inside the 50-per-account cap. Design and the verified AWS facts behind all of
it: [`../docs/SPEC.md`](../docs/SPEC.md) §4, §4.1, §4.2.

## What this does not do

**It does not enable Security Lake.** `aws_securitylake_data_lake` is absent
deliberately: enabling a lake creates buckets, Lake Formation tables and
crawlers, takes up to an hour, and in an Organization is the delegated
administrator's decision — not something a registration config should do as a
side effect of `apply`. If the lake does not exist in `var.region`, the API
refuses these resources and says so.

**It does not create the provider roles.** Security Lake creates
`AmazonSecurityLake-Provider-{source}-{region}` itself, one per source, with the
`AmazonSecurityLakePermissionsBoundary` managed policy as their boundary. This
only names who may assume them, through `provider_identity`.

## Prerequisites

1. Security Lake enabled in the target Region. In an Organization that means a
   delegated administrator is registered for `securitylake.amazonaws.com`;
   `aws organizations list-delegated-administrators --service-principal
   securitylake.amazonaws.com` tells you whether one is.
2. Credentials for an identity that may register a source:
   `glue:CreateCrawler`, `glue:CreateDatabase`, `glue:CreateTable`,
   `glue:StopCrawlerSchedule`, `iam:GetRole`, `iam:PutRolePolicy`,
   `iam:DeleteRolePolicy`, `iam:PassRole`, `lakeformation:RegisterResource`,
   `lakeformation:GrantPermissions`, `s3:ListBucket`, `s3:PutObject` — and
   `kms:CreateGrant`, `kms:DescribeKey`, `kms:GenerateDataKey` if the lake uses a
   customer-managed key.
3. The lake's bucket name, for the crawler role's policy.

## Running it

```sh
cp terraform.tfvars.example terraform.tfvars   # then fill it in
terraform init
terraform plan
terraform apply
```

`source_name_prefix` **must equal `sink.source_name`** in the connector's
`config.toml`. The name is in the S3 prefix the connector writes and in the Glue
table a query binds to, so a mismatch means objects arriving where no registered
source points. `tests/test_terraform_sources.py` holds the class suffixes here to
the sink's own naming table, but nothing can check the prefix for you.

## After applying

Read `terraform output source_locations` and compare each against the prefix the
connector derives, `ext/{source}/`. They should agree; §4.2 explains why that is
checked rather than assumed. `terraform output provider_roles` gives the roles the
connector will assume once it does — it writes with the caller's own credentials
today, which cannot write a registered source.

## Two things to know about state

**State holds the external ID.** It is marked `sensitive` so it stays out of plan
output, but Terraform state is not encrypted at rest. The local state file is
gitignored; anything shared belongs in a remote backend with encryption and
restricted access, which is deliberately not configured here because the right
backend is a deployment decision.

**A deleted source leaves its crawler behind.** AWS: Security Lake "can't delete
or update existing crawlers in your account. If you delete a custom source, we
recommend deleting the associated crawler if you plan to create a custom source
with the same name in the future." So `terraform destroy` is not a clean
reversal, and reusing a name after destroying it can collide with the orphan.
