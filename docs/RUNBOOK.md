# Standing this up in AWS

Two parts, and the split matters.

**Part A is the customer's side** — the organization, the accounts, the data lake.
A real consumer already has all of it and skips straight to Part B. It is written
down because this project's author had to build it in order to test against
something, not because the connector requires you to hand any of it over. The
connector creates only what exists *because the connector exists*; everything
else is an input (see [`../terraform/README.md`](../terraform/README.md)).

**Part B is installing the integration** — two terraform modules and the
connector.

Steps marked **[verified]** were performed and observed on the date given.
Everything else is reasoned from AWS documentation and should be treated as a
hypothesis until someone runs it.

---

# Part A — what a consumer already has

## A1. Accounts

AWS's Security Reference Architecture puts the lake in a **Log Archive** account
and security tooling in its own, with **no workloads in the management account**.
Part of that is enforced — **[verified 2026-10-03]** the management account is
refused as the Security Lake delegated administrator:

> The management account for an organization cannot be the delegated Security
> Lake administrator for the organization. Specify a different account.

```sh
aws organizations create-organizational-unit --parent-id <root-id> --name Security
aws organizations create-account --email <addr> --account-name "Log Archive"
aws organizations create-account --email <addr> --account-name "Security Tooling"
aws organizations list-create-account-status --states SUCCEEDED   # async; ids land here
aws organizations move-account --account-id <new> \
  --source-parent-id <root-id> --destination-parent-id <ou-id>
```

**The root email addresses are the one decision worth slowing down for.** Use a
group or distribution list, not a personal mailbox, on a domain you will hold
indefinitely — it is the root password-recovery path, so whoever holds that inbox
holds the account. Check three things before creating anything: the group accepts
**external** senders (AWS mails from outside your domain), it is unmoderated, and
at least one real person receives it. Test from an outside address and confirm it
lands in the inbox, not spam.

Changing the address later needs root access to that account. An address used by
a closed account can never be reused — unless you change it *before* closing.

## A2. Access

Assign permission sets to a **group**, not to users. One group membership answers
"who can administer the lake?", and it is what an external identity provider
would later drive.

```sh
aws identitystore create-group --identity-store-id <d-xxxx> --display-name AWSSecurityAdmins
aws identitystore create-group-membership --identity-store-id <d-xxxx> \
  --group-id <gid> --member-id 'UserId=<uid>'
aws sso-admin create-account-assignment --instance-arn <instance> \
  --permission-set-arn <AdministratorAccess> \
  --principal-type GROUP --principal-id <gid> \
  --target-id <account> --target-type AWS_ACCOUNT
```

Then prove it, rather than reading the API back: add a profile per account and
call `aws sts get-caller-identity --profile <name>`.

Changing the **management** account's own access comes last, and in this order:
add the new path, log out and back in to verify, *then* remove the old one. It is
the only account that can repair the others.

## A3. Centralised root access — optional, and best done now

**[verified 2026-10-08]** Two organization-wide switches that remove root
credentials from member accounts and replace break-glass with a scoped session.

```sh
aws organizations enable-aws-service-access --service-principal iam.amazonaws.com
aws iam enable-organizations-root-credentials-management
aws iam enable-organizations-root-sessions
```

The first is a prerequisite; without it the others fail with
`ServiceAccessNotEnabledException`.

Afterwards, root-only tasks are performed from the management account as a
session of at most **900 seconds**, scoped to one of five task policies —
`IAMAuditRootUserCredentials`, `IAMCreateRootUserPassword`,
`IAMDeleteRootUserCredentials`, `S3UnlockBucketPolicy`, `SQSUnlockQueuePolicy`:

```sh
aws sts assume-root --target-principal <account-id> \
  --task-policy-arn arn=arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials \
  --duration-seconds 900
```

**[verified]** Taking that session returns credentials whose identity is
`arn:aws:iam::<account>:root`, and `aws iam get-account-summary` through it
reports whether root access keys, MFA or signing certificates exist. Do this
before you need it; a break-glass path nobody has exercised is a hypothesis.

The management account's own root keeps its credentials and cannot be stripped —
you concentrate root into one account rather than eliminating it, so that one
deserves hardware MFA.

## A4. The encryption key

**[verified 2026-10-08]** A customer-managed key rules out the console:

> SSE-KMS isn't supported in the Security Lake console. To use SSE-KMS with the
> Security Lake API or CLI, you first create a KMS key…

Order matters — the key's policy names a role, so the role goes first.

```sh
aws iam create-role --role-name AmazonSecurityLakeMetaStoreManager --path /service-role/ \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
    "Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name AmazonSecurityLakeMetaStoreManager \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonSecurityLakeMetastoreManager
```

**[verified]** `lambda.amazonaws.com` is the right trust — Security Lake's ETL
runs on Lambda, the managed policy's first statement is `AllowWriteLambdaLogs`,
and the resulting lake reported no exceptions.

Then the key. Security Lake needs exactly three actions and explicitly **does
not need `Decrypt`** — S3 handles decryption for readers. **Multi-Region keys are
not allowed.**

```json
{"Version":"2012-10-17","Statement":[
 {"Sid":"EnableAccountPermissions","Effect":"Allow",
  "Principal":{"AWS":"arn:aws:iam::<log-archive>:root"},"Action":"kms:*","Resource":"*"},
 {"Sid":"AllowSecurityLakeMetaStoreManager","Effect":"Allow",
  "Principal":{"AWS":"arn:aws:iam::<log-archive>:role/service-role/AmazonSecurityLakeMetaStoreManager"},
  "Action":["kms:CreateGrant","kms:DescribeKey","kms:GenerateDataKey"],"Resource":"*"}]}
```

`arn:aws:iam::<account>:root` in a **key policy** does not mean the root user. It
means "this account's principals, as governed by IAM", and it is what keeps the
key manageable. Omit it and you have an orphaned key.

```sh
aws kms create-key --key-spec SYMMETRIC_DEFAULT --policy file://key-policy.json
aws kms enable-key-rotation --key-id <id>
aws kms create-alias --alias-name alias/security-lake --target-key-id <id>
```

## A5. The lake

```sh
aws securitylake create-data-lake \
  --configurations '[{"encryptionConfiguration":{"kmsKeyId":"<key-id>"},
                      "region":"us-east-1",
                      "lifecycleConfiguration":{"expiration":{"days":90}}}]' \
  --meta-store-manager-role-arn arn:aws:iam::<log-archive>:role/service-role/AmazonSecurityLakeMetaStoreManager
```

Run as the **delegated administrator** account. Retention of 90 days matches
Okta's own retention window, so the lake holds exactly as much history as the
source could ever replay. No storage-class transitions — at this volume they add
Glacier minimums for no saving.

**[verified 2026-10-08]** Creation completed in minutes rather than the hour the
provider's timeouts allow for. Check both of these before trusting it:

```sh
aws securitylake list-data-lakes --regions us-east-1 \
  --query 'dataLakes[].{status:createStatus,encryption:encryptionConfiguration.kmsKeyId,retentionDays:lifecycleConfiguration.expiration.days}'
aws securitylake list-data-lake-exceptions --regions us-east-1
```

An empty exception list is how you learn the meta store manager role's trust
policy was right.

**Leave the AWS-native log sources off** unless you want them. CloudTrail is
$0.75/GB and VPC flow logs generate real volume. **[verified]** custom sources
cost nothing: *"There is no Security Lake charge for bringing third-party or your
own data to centralize in Security Lake."*

Two things AWS leaves to you that an enterprise would fix: Security Lake creates
**two unencrypted SQS queues** in the delegated administrator account, and
nothing subscribes to ingestion failures — see
`create-data-lake-exception-subscription`.

---

# Part B — installing the integration

Everything from here is the connector, and is what a consumer with the above
already in place actually does.

## B1. State

A backend cannot create its own storage. One bucket per account, versioned,
encrypted, public access blocked.

```sh
aws s3api create-bucket --bucket <tfstate-bucket> --region us-east-1
aws s3api put-bucket-versioning --bucket <tfstate-bucket> \
  --versioning-configuration Status=Enabled
aws s3api put-public-access-block --bucket <tfstate-bucket> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

`us-east-1` takes no `--create-bucket-configuration`; every other Region requires
one.

## B2. The connector's role — security-tooling

```sh
cd terraform/security-tooling
cp terraform.tfvars.example terraform.tfvars    # leave provider_role_arns = []
terraform init -backend-config=bucket=<tfstate-bucket> \
               -backend-config=key=security-tooling/terraform.tfstate \
               -backend-config=region=us-east-1
terraform apply
terraform output connector_role_arn
```

`trusted_principals` is whoever may assume it. Read your own rather than guessing
— an SSO role ARN carries a generated suffix:

```sh
aws sts get-caller-identity --query Arn --output text
```

Set `permissions_boundary` if your organization requires one on every role.

## B3. Register the custom sources — log-archive · IRREVERSIBLE

```sh
cd terraform/log-archive
cp terraform.tfvars.example terraform.tfvars    # provider_principal = B2's output
export TF_VAR_provider_external_id="$(openssl rand -hex 16)"   # keep this
terraform init -backend-config=bucket=<tfstate-bucket> \
               -backend-config=key=log-archive/terraform.tfstate \
               -backend-config=region=us-east-1
terraform plan      # read it
terraform apply
```

There is no `update-custom-log-source`, and deleting a source leaves its Glue
crawler behind — so the **source names** and the **provider principal** are
effectively permanent here. Supply `crawler_role_arn` if you already have a
crawler role; omit it and one is created.

Watch for one thing: **`okta_base_event` declares no event class**, because Base
Event is absent from the list AWS accepts while unknown Okta event types degrade
to it. `eventClasses` is optional, so this apply answers whether a source may be
registered without one — issue `pet.11.3`, and this is the experiment.

Keep the external id. The connector needs the same value and nothing prints it
back.

## B4. Bind the connector's one privilege — security-tooling

```sh
cd terraform/log-archive && terraform output -json provider_roles
cd ../security-tooling   # put those ARNs in provider_role_arns
terraform apply
```

## B5. Check the prefix agrees

```sh
cd terraform/log-archive && terraform output source_locations
```

Each should end in the prefix the connector derives, `ext/{source}/`. A silent
disagreement writes objects no Glue table points at, which from outside looks
exactly like a stream with nothing to ship (SPEC §4.2).

## B6. Configure and run

```toml
[sink]
kind   = "s3"
bucket = "aws-security-data-lake-..."

[sink.provider_roles]
# the seven ARNs from B4
```

```sh
export OCSF_SINK_EXTERNAL_ID="<the value from B3>"
export AWS_PROFILE=security-tooling     # resolving to the connector's role
uv run ocsf-connector backfill --since <t0> --until <t1>
aws s3 ls s3://<lake bucket>/ext/okta_authentication/ --recursive | head
```

Configuration refuses a role map that is not exactly the sources this connector
writes, so a missing or spare entry fails at load rather than at the first flush
that happens to carry that class.

## B7. Crawl, then query

Security Lake creates a crawler per source and recommends running it manually
when new columns appear. Until it has, Athena returns nothing — which is not the
same as delivery having failed.

**The programmatic path requires an explicit grant**, quoted from AWS:

> When you programmatically enable Security Lake, database view permissions
> aren't granted automatically. The data lake administrator account in AWS Lake
> Formation must grant `SELECT` permissions to the IAM role you want to use to
> query the relevant databases and tables.

So whoever queries needs a Lake Formation `SELECT` grant, separate from any
permission to write.

---

## Shortcuts that remain

- **The connector runs by hand**, under a human identity assuming the role.
  Compute with that role attached — ECS task role, EKS IRSA, EC2 instance profile
  — needs no re-registration, because the sources trust the role rather than
  whoever assumed it.
- **The Okta private key is a file on disk.** `ocsf-connector-pet.12` moves it to
  Secrets Manager; `OktaClientCredentials` already takes PEM text rather than a
  path, so it is additive.
- **Security Lake's two SQS queues are unencrypted**, and nothing subscribes to
  ingestion exceptions.
- **No container image**, which is what stands between this and something a
  consumer can deploy.
