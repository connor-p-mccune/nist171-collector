###############################################################################
# S3 buckets
#
# Three buckets: one configured properly, one left bare, and one holding the
# CloudTrail logs.
#
# Note on structure: since AWS provider v4, aws_s3_bucket no longer accepts
# inline versioning / encryption / policy / public access block arguments. Each
# is its own resource now. That is why one "compliant bucket" is five resources.
###############################################################################

# ---------------------------------------------------------------------------
# COMPLIANT bucket -- should produce PASS for 3.1.13 and 3.1.20
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "compliant" {
  bucket        = "${local.name_prefix}-compliant-${local.suffix}"
  force_destroy = true # test data only; lets terraform destroy clean up objects
}

resource "aws_s3_bucket_versioning" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  rule {
    apply_server_side_encryption_by_default {
      # No kms_master_key_id, so this uses the AWS-managed aws/s3 key, which is
      # free. A customer-managed key would satisfy the same requirement and cost
      # about $1/month.
      sse_algorithm = "aws:kms"
    }
    # Cuts KMS request costs by reusing a data key. Free either way at this size.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "compliant" {
  bucket = aws_s3_bucket.compliant.id
  policy = data.aws_iam_policy_document.compliant_tls_only.json

  # The public access block must exist first, otherwise block_public_policy can
  # race with the policy write.
  depends_on = [aws_s3_bucket_public_access_block.compliant]
}

data "aws_iam_policy_document" "compliant_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.compliant.arn,
      "${aws_s3_bucket.compliant.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# ---------------------------------------------------------------------------
# NON-COMPLIANT bucket -- deliberately bare. No encryption, no versioning, no
# public access block, no policy. Should produce FAIL for 3.1.13 and 3.1.20.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "noncompliant" {
  bucket        = "${local.name_prefix}-noncompliant-${local.suffix}"
  force_destroy = true
}

# ---------------------------------------------------------------------------
# CloudTrail log bucket -- protected, because 3.3.8 asks whether the audit trail
# itself is safe from tampering.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "trail" {
  bucket        = "${local.name_prefix}-trail-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket = aws_s3_bucket.trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

data "aws_iam_policy_document" "trail_bucket" {
  # CloudTrail checks the bucket ACL before it starts writing.
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]

    # Scopes the grant to this one trail. Without it, any CloudTrail trail in
    # any account could be pointed at this bucket -- the confused deputy problem.
    # The ARN is built by hand rather than referenced, because referencing the
    # trail here would create a dependency cycle: trail needs policy needs trail.
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.trail.arn,
      "${aws_s3_bucket.trail.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}
