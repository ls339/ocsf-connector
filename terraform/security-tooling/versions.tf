terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Partial, like the log-archive module's: bucket and key are passed at init.
  # Separate state from log-archive, deliberately -- the two accounts are reached
  # with different credentials, and one state file holding both would mean one
  # identity able to change both.
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region              = var.region
  profile             = var.aws_profile
  allowed_account_ids = [var.account_id]
}
