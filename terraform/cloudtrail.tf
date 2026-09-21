###############################################################################
# CloudTrail
#
# Fully compliant on purpose. This is the audit logging the whole 3.3.x family
# is about, and it gives the scanner a clear set of PASS cases.
#
# Cost: one trail delivering a single copy of management events is free. Adding
# a second trail, or data events, would start charging.
###############################################################################

resource "aws_cloudtrail" "main" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.trail.id

  # Records activity in every region, not just us-east-1 -- 3.3.1.
  is_multi_region_trail = true

  # Includes IAM, STS and other global services, without which you cannot trace
  # an IAM change back to the user who made it -- 3.3.2.
  include_global_service_events = true

  # Writes a signed digest file so log tampering is detectable -- 3.3.8. This is
  # the CloudTrail equivalent of the SHA-256 hashing the scanner does on its own
  # evidence.
  enable_log_file_validation = true

  enable_logging = true

  # CloudTrail validates it can write to the bucket at creation time, so the
  # bucket policy has to be in place first. Terraform infers most ordering from
  # references, but here the dependency runs through AWS rather than through a
  # value, so it has to be stated.
  depends_on = [aws_s3_bucket_policy.trail]
}
