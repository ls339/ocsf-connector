# Pinned because this configuration creates a Glue table an Athena query binds
# to: a provider that changes how a custom source is registered changes what the
# lake looks like, and that should be a deliberate upgrade.
terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Deliberately partial: the bucket and key are passed with -backend-config at
  # init, because they name an account's own state bucket and this file is
  # public. `use_lockfile` is S3-native locking -- DynamoDB-based locking is
  # deprecated -- and `encrypt` has no default worth relying on, so it is stated.
  # >= 1.11 is for use_lockfile.
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  # The guard that matters in a three-account layout. Credentials that resolve to
  # any other account make this a refusal rather than an incident -- registering
  # custom sources in the wrong account is not something you want to undo, since
  # deleting one leaves its Glue crawler behind.
  allowed_account_ids = [var.account_id]
}
