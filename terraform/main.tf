###############################################################################
# nist171-collector test environment
#
# Creates a small AWS environment that is deliberately PART compliant and PART
# non-compliant, so the scanner has real PASS and FAIL cases to find. See
# EXPECTED.md for what each resource is supposed to produce.
#
# THIS IS NOT A REFERENCE ARCHITECTURE. Several resources here are insecure on
# purpose. Never apply this to an account that holds anything real.
#
# Cost: designed to be $0 or near it. No NAT gateways, no EC2 instances, no
# AWS Config, GuardDuty, Security Hub or Inspector. The one CloudTrail trail is
# within the always-free tier for a single copy of management events, and the
# S3 buckets hold kilobytes. Encryption uses the AWS-managed aws/s3 KMS key,
# which is free -- a customer-managed key would cost about $1/month.
###############################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

variable "aws_profile" {
  description = "AWS named profile used to create these resources. Pass nist-admin; the scanner profile cannot create anything."
  type        = string
  # No default on purpose. Requiring it on the command line makes it impossible
  # to apply this by accident against whatever profile happens to be current.
}

provider "aws" {
  region  = "us-east-1"
  profile = var.aws_profile

  # default_tags applies these to every taggable resource this provider creates,
  # so nothing can be missed and the whole test environment is findable by tag.
  default_tags {
    tags = {
      Project     = "nist171-collector"
      Environment = "test"
    }
  }
}

data "aws_caller_identity" "current" {}

# S3 bucket names are globally unique across all AWS accounts, so a fixed name
# would collide with anyone else who ran this. A random suffix avoids that.
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  region      = "us-east-1"
  account_id  = data.aws_caller_identity.current.account_id
  name_prefix = "nist171-test"
  suffix      = random_id.suffix.hex

  trail_name = "nist171-test-main"

  # Built by hand rather than referenced from aws_cloudtrail.main, because the
  # trail's bucket policy has to name this ARN and the trail cannot be created
  # until that policy exists. Referencing the resource would be a cycle.
  trail_arn = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}
