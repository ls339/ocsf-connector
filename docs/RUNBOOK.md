# Standing this up in AWS

The order matters, three steps are effectively irreversible, and two of those
decide values you cannot change afterwards. This is the procedure; the reasoning
behind the architecture is [`SPEC.md`](SPEC.md) §4.2.

**Written before it had ever been run end to end.** Where a step has been
verified live, it says so. Where it has not, treat it as a hypothesis and expect
to correct this file.

## The accounts

```
management         creates accounts, registers the delegated admin. No workloads.
log-archive        Security Lake delegated administrator. The lake, the seven
                   custom sources, the roles Security Lake creates for them.
security-tooling   the role the connector runs as.
```

This is AWS's Security Reference Architecture applied to one connector, and part
of it is enforced: **the management account cannot be the Security Lake delegated
administrator** — verified 2026-10-03 by being refused:

> The management account for an organization cannot be the delegated Security
> Lake administrator for the organization. Specify a different account.

## What cannot be changed later

Settle these before step 5. There is no `update-custom-log-source`, and deleting
a custom source leaves its Glue crawler behind, so a correction means delete,
recreate under a name that may collide with the orphan, and rewrite anything
already published under the old prefix.

| decision | why it sticks |
|---|---|
| which account is the delegated administrator | the lake, its bucket and its roles live there |
| `provider_principal` — the connector's **role ARN** | baked into each source's trust at registration |
| the custom source names | in the S3 prefix and the Glue table a query binds to |
| the lake's encryption | chosen at `create-data-lake` |

## 0. Bootstrap state storage — once, before any terraform

A backend cannot create its own bucket. One bucket per account, versioned,
encrypted, public access blocked:

```sh
aws s3api create-bucket --bucket <tfstate-bucket> --region us-east-1 --profile <profile>
aws s3api put-bucket-versioning --bucket <tfstate-bucket> \
  --versioning-configuration Status=Enabled --profile <profile>
aws s3api put-public-access-block --bucket <tfstate-bucket> --profile <profile> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

`us-east-1` takes no `--create-bucket-configuration`; every other Region requires
one. Versioning is what lets you recover a state file somebody truncated.

## 1. Create the two accounts — management account

```sh
aws organizations create-account --email <unique-address> --account-name log-archive
aws organizations create-account --email <unique-address> --account-name security-tooling
aws organizations list-create-account-status --states SUCCEEDED   # ids land here
```

Each needs an email address no AWS account has used. An account is effectively
permanent: closing one suspends it for 90 days and it still counts against your
quota.

Then grant yourself access to both — an SSO permission set assignment, or the
`OrganizationAccountAccessRole` the organization creates in each new account.

## 2. Designate the delegated administrator — management account

```sh
aws securitylake register-data-lake-delegated-administrator \
  --account-id <log-archive account id>
```

## 3. Enable the lake — log-archive account

Console *Get started* is the gentler path: it creates the meta-store-manager role
and the service-linked roles that the CLI expects you to have already.

Choose a **customer-managed KMS key**, not SSE-S3. Security Lake attaches
`kms:Decrypt` and `kms:GenerateDataKey` to the provider roles itself, so the
connector needs nothing for it — but the Glue crawler role is ours, and
`lake_kms_key_arn` in the log-archive module is what lets a crawler read what it
is meant to describe.

**Leave the AWS-native log sources off** unless you want them. CloudTrail and VPC
flow logs cost real money and are unrelated to this connector.

Allow up to an hour. Then record the bucket:

```sh
aws securitylake list-data-lakes --regions us-east-1 --query 'dataLakes[].s3BucketArn'
```

## 4. Create the connector's role — security-tooling account

```sh
cd terraform/security-tooling
cp terraform.tfvars.example terraform.tfvars    # fill in; leave provider_role_arns = []
terraform init -backend-config=bucket=<tfstate-bucket> \
               -backend-config=key=security-tooling/terraform.tfstate \
               -backend-config=region=us-east-1
terraform apply
terraform output connector_role_arn
```

`trusted_principals` is who may assume it. While you run the connector by hand
that is your own identity — read it, do not guess it, because an SSO role ARN
carries a generated suffix:

```sh
aws sts get-caller-identity --query Arn --output text
```

## 5. Register the custom sources — log-archive account · IRREVERSIBLE

```sh
cd terraform/log-archive
cp terraform.tfvars.example terraform.tfvars    # provider_principal = step 4's output
export TF_VAR_provider_external_id="$(openssl rand -hex 16)"   # keep this
terraform init -backend-config=bucket=<tfstate-bucket> \
               -backend-config=key=log-archive/terraform.tfstate \
               -backend-config=region=us-east-1
terraform plan      # read it
terraform apply
```

Two things to watch:

- **`okta_base_event` declares no event class**, because Base Event is absent from
  the list AWS accepts and unknown Okta event types degrade to it (invariant 4).
  `eventClasses` is optional, so this apply answers whether a source may be
  registered without one. That is issue `pet.11.3`, and this is the experiment.
- Keep the external id. The connector needs the same value, and nothing will
  print it back to you.

## 6. Bind the connector's one privilege — security-tooling account

```sh
cd terraform/log-archive && terraform output -json provider_roles
cd ../security-tooling   # put those ARNs in provider_role_arns
terraform apply
```

## 7. Check the prefix agrees — before trusting any delivery

```sh
cd terraform/log-archive && terraform output source_locations
```

Each should end in the prefix the connector derives, `ext/{source}/`. A silent
disagreement writes objects no Glue table points at, which from the outside looks
exactly like a stream with nothing to ship (§4.2).

## 8. Configure the connector

```toml
[sink]
kind   = "s3"
bucket = "aws-security-data-lake-..."

[sink.provider_roles]
# the seven ARNs from step 6
```

```sh
export OCSF_SINK_EXTERNAL_ID="<the value from step 5>"
export AWS_PROFILE=security-tooling   # resolving to the connector's role
```

Configuration refuses a role map that is not exactly the sources this connector
writes, so a missing or spare entry fails at load rather than at the first flush
that happens to carry that class.

## 9. First delivery

A bounded backfill over a short window, rather than a tail:

```sh
uv run ocsf-connector backfill --since 2026-10-03T00:00:00Z --until 2026-10-03T01:00:00Z
aws s3 ls s3://<lake bucket>/ext/okta_authentication/ --recursive | head
```

The summary line says what it did. The objects should appear under
`ext/{source}/region=.../accountId=external_.../eventDay=.../`.

## 10. Crawl, then query

Security Lake creates a crawler per source and recommends running it manually
when new columns appear. Until it has run, Athena returns nothing — which is not
the same as delivery having failed.

The identity doing the querying may also need a **Lake Formation grant** on the
table, which is separate from permission to write it.

## What is still a shortcut after all this

- **The connector runs by hand**, under a human identity assuming the role. The
  fix is compute with that role attached — ECS task role, EKS IRSA, EC2 instance
  profile — and it needs no re-registration, because the sources trust the role
  rather than whoever assumed it.
- **The Okta private key is a file on disk.** `ocsf-connector-pet.12` moves it to
  Secrets Manager; `OktaClientCredentials` already takes PEM text rather than a
  path, so it is additive.
- **No ingestion-failure alerting.** Security Lake has
  `create-data-lake-exception-subscription`; nothing here subscribes.
- **No retention policy** on the lake beyond whatever was chosen at creation.
