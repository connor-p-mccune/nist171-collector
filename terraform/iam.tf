###############################################################################
# IAM
#
# One well-scoped policy, and then three deliberate problems: a wildcard policy,
# a weak password policy, and a user holding AdministratorAccess with no MFA.
###############################################################################

# ---------------------------------------------------------------------------
# COMPLIANT -- a policy scoped to one action on one resource. Exists so the
# wildcard check has something correct to ignore: a check that flags everything
# is as useless as one that flags nothing.
# ---------------------------------------------------------------------------

resource "aws_iam_policy" "least_privilege" {
  name        = "${local.name_prefix}-least-privilege"
  description = "Read one object path in the compliant bucket. Correctly scoped example."
  policy      = data.aws_iam_policy_document.least_privilege.json
}

data "aws_iam_policy_document" "least_privilege" {
  statement {
    sid       = "ReadCompliantBucketObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.compliant.arn}/*"]
  }
}

# ---------------------------------------------------------------------------
# NON-COMPLIANT -- Allow * on *. Should produce FAIL for 3.1.2.
# ---------------------------------------------------------------------------

resource "aws_iam_policy" "too_permissive" {
  name        = "nist171-test-overly-permissive"
  description = "DELIBERATELY INSECURE. Allow all actions on all resources, for scanner testing."
  policy      = data.aws_iam_policy_document.too_permissive.json
}

data "aws_iam_policy_document" "too_permissive" {
  statement {
    sid       = "AllowEverything"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

# ---------------------------------------------------------------------------
# NON-COMPLIANT -- a password policy that fails every complexity requirement.
# Should produce PASS for 3.5.2 (a policy does exist) but FAIL for 3.5.7 and
# 3.5.8. That split is the point: existence and adequacy are different checks.
#
# ACCOUNT-WIDE: there is only one password policy per AWS account, so applying
# this replaces whatever the account had. terraform destroy removes it again.
# ---------------------------------------------------------------------------

resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 8
  require_symbols                = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_lowercase_characters   = false
  password_reuse_prevention      = 1
  allow_users_to_change_password = true
}

# ---------------------------------------------------------------------------
# NON-COMPLIANT -- a user with AdministratorAccess attached directly and no MFA.
# Should produce FAIL for 3.1.5 (least privilege) and 3.5.3 (MFA on privileged
# accounts).
#
# No console password and no access keys are created, so this user cannot
# actually sign in or call anything. It exists only as a configuration the
# scanner can find.
# ---------------------------------------------------------------------------

resource "aws_iam_user" "no_mfa_user" {
  name          = "nist171-test-user"
  force_destroy = true
}

resource "aws_iam_user_policy_attachment" "no_mfa_user_admin" {
  user       = aws_iam_user.no_mfa_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
