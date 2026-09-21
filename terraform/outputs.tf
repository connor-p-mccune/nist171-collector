###############################################################################
# Outputs
#
# Printed after apply, and readable later with `terraform output`. Use these to
# confirm the scanner is looking at the resources you think it is.
###############################################################################

output "compliant_bucket_name" {
  description = "Bucket configured correctly: KMS encryption, versioning, public access block, TLS-only policy."
  value       = aws_s3_bucket.compliant.id
}

output "noncompliant_bucket_name" {
  description = "Bucket left deliberately bare: no encryption, versioning, public access block or policy."
  value       = aws_s3_bucket.noncompliant.id
}

output "trail_bucket_name" {
  description = "Bucket holding the CloudTrail logs."
  value       = aws_s3_bucket.trail.id
}

output "trail_arn" {
  description = "ARN of the multi-region CloudTrail trail."
  value       = aws_cloudtrail.main.arn
}

output "test_user_name" {
  description = "IAM user with AdministratorAccess and no MFA."
  value       = aws_iam_user.no_mfa_user.name
}

output "open_security_group_id" {
  description = "Security group allowing SSH and RDP from 0.0.0.0/0."
  value       = aws_security_group.open_ssh.id
}
