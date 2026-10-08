# Terraform: the three accounts this needs

Two root modules, one per account, with separate state. They are separate because
the accounts are reached with different credentials — one state file spanning both
would mean one identity able to change both, which is the thing the layout exists
to avoid.

```
log-archive/        the Security Lake delegated administrator. The data lake's
                    custom sources (one per OCSF class), and the Glue crawler
                    role the API path requires.
security-tooling/   the IAM role the connector runs as, and its one privilege:
                    permission to assume the per-source provider roles.
```

Nothing here belongs in the organization's **management account**, which under
AWS's Security Reference Architecture runs no workloads. AWS enforces part of
this itself: the management account cannot be the Security Lake delegated
administrator.

Design and the verified AWS facts behind all of it:
[`../docs/SPEC.md`](../docs/SPEC.md) §4, §4.1, §4.2. The procedure for standing it
up, in order, with the irreversible steps marked:
[`../docs/RUNBOOK.md`](../docs/RUNBOOK.md).

## What you already have, and what this adds

The rule these modules are built to: **create only what exists because the
connector exists.** Everything else is an input. A connector has no business
managing an organisation's infrastructure, and a module that insists on creating
a key, a bucket or a role to someone else's conventions is one that gets refused
at review.

So this assumes a consumer already has:

| | |
|---|---|
| an AWS Organization | with somewhere sensible for security accounts to live |
| **Security Lake enabled** in the target Region | with its delegated administrator, encryption key and retention already decided |
| an IaC pipeline | with remote state, which is why both backends here are partial |
| a Glue crawler role | *optionally* — supply `crawler_role_arn` and we use theirs |
| an Okta tenant | with an API Services app scoped to `okta.logs.read` |

And adds only:

| | |
|---|---|
| seven custom log sources | these *are* the integration |
| the role the connector runs as | and its single privilege: assuming the seven provider roles |
| a Glue crawler role | only when one was not supplied |

It never touches the lake, the bucket, the key, the accounts or the organisation.
If you are standing up the customer side yourself in order to test — as this
project's author is — that is [`../docs/RUNBOOK.md`](../docs/RUNBOOK.md) Part A,
kept deliberately separate so nobody mistakes our demo scaffolding for something
the product requires you to hand over.

## What these modules do not do

**They do not enable Security Lake.** `aws_securitylake_data_lake` is absent
deliberately: enabling a lake creates buckets, Lake Formation tables and
crawlers, takes up to an hour, and is a decision about an organization rather
than a side effect of registering a source. The runbook covers it.

**They do not create the provider roles.** Security Lake creates
`AmazonSecurityLake-Provider-{source}-{region}` itself, one per source, bounded
by the `AmazonSecurityLakePermissionsBoundary` managed policy. These modules only
name who may assume them.

**They do not create the state bucket.** A backend cannot bootstrap its own
storage. Both backends are partial — `bucket` and `key` are passed at `init` —
because those name real buckets and this file is public.

## Three applies, in this order

The ordering is inherent, not an accident of layout: the connector's role must
exist before a custom source can be registered to trust it, and the roles those
sources produce do not exist until they are registered.

1. **`security-tooling`** with `provider_role_arns = []`. Creates the connector's
   role, which can do nothing yet.
2. **`log-archive`** with `provider_principal` set to that role's ARN. Registers
   the seven sources. This is the irreversible one: there is no
   `update-custom-log-source`, and deleting a source leaves its Glue crawler
   behind, so the principal and the source names are effectively permanent.
3. **`security-tooling`** again, with `provider_role_arns` filled from
   `terraform output provider_roles`. Grants the role its one privilege.

## Afterwards

Compare `terraform output source_locations` against the prefix the connector
derives, `ext/{source}/`. They should agree; §4.2 explains why that is checked
rather than assumed.

## Two things to know about state

**State holds the external id.** It is marked `sensitive`, so it stays out of
plan output, but Terraform state is not encrypted by Terraform. `encrypt = true`
on the backend is why the bucket must have encryption, and why the state bucket
should be as restricted as the lake.

**A deleted source leaves its crawler behind.** AWS: Security Lake "can't delete
or update existing crawlers in your account. If you delete a custom source, we
recommend deleting the associated crawler if you plan to create a custom source
with the same name in the future." So `destroy` is not a clean reversal, and
reusing a name after destroying it can collide with the orphan.
