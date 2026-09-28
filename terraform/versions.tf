# Pinned because this configuration creates a Glue table an Athena query binds
# to: a provider that changes how a custom source is registered changes what the
# lake looks like, and that should be a deliberate upgrade.
terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}
