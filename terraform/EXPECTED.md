# Expected scanner results for the test environment

This is the answer key. Every resource in `terraform/` exists to drive a specific
outcome in the scanner. If the scanner disagrees with this file, one of the two is
wrong — and finding out which is the point of having it.

**Warning:** several resources here are deliberately insecure. This is for a throwaway
AWS account only.

---

## 1. Per-resource expectations

"Expected" means what this resource should contribute. **PASS** = the resource is
configured correctly and must *not* appear in the check's affected-resources list.
**FAIL** = the resource is the problem and must be named by the check.

| # | Resource | Requirement | Check | Expected |
|---|---|---|---|---|
| 1 | `aws_s3_bucket_public_access_block.compliant` | 3.1.20 | `s3_public_access_blocked` | PASS |
| 2 | `aws_s3_bucket_policy.compliant` (TLS-only deny) | 3.1.13 | `s3_requires_tls` | PASS |
| 3 | `aws_s3_bucket_versioning.compliant` | 3.1.20 | supporting evidence | PASS |
| 4 | `aws_s3_bucket_server_side_encryption_configuration.compliant` | 3.1.13 | supporting evidence | PASS |
| 5 | `aws_s3_bucket_policy.trail` (TLS-only deny) | 3.1.13 | `s3_requires_tls` | PASS |
| 6 | `aws_s3_bucket_versioning.trail` + `..._public_access_block.trail` | 3.3.8 | `cloudtrail_bucket_protected` | PASS |
| 7 | `aws_cloudtrail.main` — `is_multi_region_trail`, logging on | 3.3.1 | `cloudtrail_enabled_multiregion` | PASS |
| 8 | `aws_cloudtrail.main` — `enable_log_file_validation` | 3.3.8 | `cloudtrail_log_validation` | PASS |
| 9 | `aws_cloudtrail.main` — `include_global_service_events` | 3.3.2 | `cloudtrail_global_events` | PASS |
| 10 | `aws_iam_policy.least_privilege` | 3.1.2 | `iam_no_wildcard_admin_policies` | PASS |
| 11 | `aws_iam_account_password_policy.weak` — exists at all | 3.5.2 | `password_policy_exists` | PASS |
| 12 | `aws_iam_user.no_mfa_user` — no console password | 3.5.3 | `mfa_all_users` | PASS |
| 13 | `aws_s3_bucket.noncompliant` — no public access block | 3.1.20 | `s3_public_access_blocked` | **FAIL** |
| 14 | `aws_s3_bucket.noncompliant` — no bucket policy | 3.1.13 | `s3_requires_tls` | **FAIL** |
| 15 | `aws_iam_policy.too_permissive` — `Allow * on *` | 3.1.2 | `iam_no_wildcard_admin_policies` | **FAIL** |
| 16 | `aws_iam_user_policy_attachment.no_mfa_user_admin` | 3.1.5 | `iam_least_privilege_admin` | **FAIL** |
| 17 | `aws_iam_user.no_mfa_user` — admin rights, no MFA | 3.5.3 | `mfa_privileged_users` | **FAIL** |
| 18 | `aws_security_group.open_ssh` — port 22 from `0.0.0.0/0` | 3.1.12 | `sg_no_unrestricted_admin_ingress` | **FAIL** |
| 19 | `aws_security_group.open_ssh` — port 3389 from `0.0.0.0/0` | 3.1.12 | `sg_no_unrestricted_admin_ingress` | **FAIL** |
| 20 | `aws_iam_account_password_policy.weak` — length 8, no character classes | 3.5.7 | `password_complexity` | **FAIL** |
| 21 | `aws_iam_account_password_policy.weak` — `password_reuse_prevention = 1` | 3.5.8 | `password_reuse` | **FAIL** |
| 22 | `aws_s3_bucket.noncompliant` — no encryption | (SC family, out of scope) | evidence only | **FAIL** in spirit, not scored |

12 PASS rows, 9 FAIL rows that are scored, plus one unscored.

Note row 11 against row 20/21: the same password policy produces a PASS and two FAILs.
That is deliberate. "A password policy exists" and "the password policy is adequate" are
different questions, and 800-171 asks both separately (3.5.2 vs 3.5.7 and 3.5.8). A
scanner that collapses them into one verdict is losing information an assessor needs.

---

## 2. Per-check expectations

This is the table to compare a real `nist171 assess` run against. A check's verdict
covers the whole account, so one bad resource makes the whole check FAIL even when other
resources are fine — that is why `s3_public_access_blocked` is FAIL overall despite the
compliant bucket being correct.

| Requirement | Check | Expected verdict | Why |
|---|---|---|---|
| 3.1.1 | `iam_users_have_mfa` | PASS | No IAM user has a console password; root MFA was enabled during setup |
| 3.1.1 | `iam_no_stale_access_keys` | PASS | Account is new; no key is 90 days old yet |
| 3.1.2 | `iam_no_wildcard_admin_policies` | **FAIL** | `nist171-test-overly-permissive` allows `*` on `*` |
| 3.1.5 | `iam_least_privilege_admin` | **FAIL** | `nist171-test-user` (and `nist-admin`) hold AdministratorAccess directly |
| 3.1.12 | `sg_no_unrestricted_admin_ingress` | **FAIL** | `nist171-test-open-ssh` allows 22 and 3389 from `0.0.0.0/0` |
| 3.1.13 | `s3_requires_tls` | **FAIL** | The non-compliant bucket has no policy |
| 3.1.20 | `s3_public_access_blocked` | **FAIL** | The non-compliant bucket has no public access block |
| 3.3.1 | `cloudtrail_enabled_multiregion` | PASS | Multi-region trail, logging enabled |
| 3.3.2 | `cloudtrail_global_events` | PASS | `include_global_service_events = true` |
| 3.3.2 | `no_shared_accounts_heuristic` | **FAIL** (likely) | Heuristic flags `nist-admin` for containing "admin" with no person's name |
| 3.3.8 | `cloudtrail_log_validation` | PASS | `enable_log_file_validation = true` |
| 3.3.8 | `cloudtrail_bucket_protected` | PASS | Trail bucket has versioning and a full public access block |
| 3.5.1 | `iam_users_identified` | PASS | `list_users` succeeded (deliberately a weak check) |
| 3.5.2 | `password_policy_exists` | PASS | The weak policy still counts as existing |
| 3.5.3 | `mfa_privileged_users` | **FAIL** | Privileged users have no MFA; expect the 3-point partial deduction, not 5 |
| 3.5.3 | `mfa_all_users` | PASS | No user has a console password, so none needs MFA under this check |
| 3.5.7 | `password_complexity` | **FAIL** | Length 8 (needs 14) and no character-class requirements |
| 3.5.8 | `password_reuse` | **FAIL** | `PasswordReusePrevention = 1` (needs 24) |
| 3.5.10 | `no_root_access_keys` | PASS | No access keys were created for root during setup |

Requirements marked MANUAL — 3.1.3, 3.1.4, 3.1.7, 3.3.3, 3.3.4, 3.3.5, 3.3.6, 3.3.7,
3.3.9, 3.5.4, 3.5.5, 3.5.6, 3.5.9, 3.5.11 — should report MANUAL regardless of what
Terraform created. No AWS API answers them.

---

## 3. Results that depend on the account, not on Terraform

Some verdicts come from how the account was set up in Part 2, not from anything in
`terraform/`. If a run disagrees with the table above, check these first.

- **`nist-admin` holds AdministratorAccess.** It is a second offender for 3.1.5 and
  3.5.3 alongside `nist171-test-user`. Expect two names in those findings, not one.
- **Root MFA.** Enabled in Part 2.3. If it were not, `iam_users_have_mfa` would FAIL.
- **Root access keys.** None were created, so 3.5.10 passes. Creating any would flip it.
- **No console passwords.** Neither `nist-admin` nor `nist-scanner` has one, which is why
  `mfa_all_users` passes and `iam_users_have_mfa` finds nothing.
- **The shared-account heuristic** flags names containing "admin" without a person's
  name. `nist-admin` will probably trip it. That is a heuristic, not a rule, and the
  finding's summary must say so.
- **AccessDenied on some S3 calls.** The `SecurityAudit` managed policy does not always
  cover `s3:GetBucketPolicy` or `s3:GetObjectLockConfiguration`. If those come back as
  errors in `s3.json`, the affected checks should report ERROR, not PASS, and the gap
  belongs in the README's limitations section.

---

## 4. Expected score

Nine scored requirements fail. Using the DoD Assessment Methodology v1.2.1 point values:

| Requirement | Points | Note |
|---|---|---|
| 3.1.2 | 5 | |
| 3.1.5 | 3 | |
| 3.1.12 | 5 | |
| 3.1.13 | 5 | |
| 3.1.20 | 1 | |
| 3.3.2 | 3 | via the shared-account heuristic |
| 3.5.3 | 3 | partial credit, not the full 5 |
| 3.5.7 | 1 | |
| 3.5.8 | 1 | |
| **Total deducted** | **27** | |

Expected score: **110 − 27 = 83**, reported as partial, with the count of requirements
actually assessed out of 110. Treat this as an estimate — it moves if a check errors out
or if the heuristic does not fire. The number the tool prints is the real one.
