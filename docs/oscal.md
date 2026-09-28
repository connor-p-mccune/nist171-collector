# OSCAL output

`nist171 report --format oscal` writes `output/oscal-assessment-results.json`, an
[OSCAL](https://pages.nist.gov/OSCAL/) **1.1.3 assessment-results** document built from
`output/findings.json`. `--format all` includes it alongside the HTML report and POA&M.

It validates against the official NIST OSCAL 1.1.3 JSON schema. That is tested on every
run, not assumed — see [Validating it](#validating-it).

## What is in it

| OSCAL element | Contents |
|---|---|
| `metadata` | Title with the AWS account ID, OSCAL version, tool version, an `assessor` role and the tool as the responsible party |
| `import-ap` | Points at a placeholder assessment plan in `back-matter` (there is no formal plan) |
| `results[0]` | One result covering this run: start = evidence collection time, end = assessment time, description = the scope note |
| `reviewed-controls` | Only the requirements actually assessed. MANUAL and unevaluable requirements are left out and named in `remarks` instead |
| `observations` | One per check, PASS / FAIL / MANUAL / ERROR / N/A alike |
| `findings` | One per FAIL, targeting the SP 800-171A objective as `not-satisfied` and linked to its observation |
| `local-definitions` | Each affected AWS resource as an `inventory-item`, so observation subjects resolve |
| `back-matter` | The evidence manifest and each evidence file, with native OSCAL SHA-256 hashes |
| `props` on the result | SPRS score, max score, requirements assessed, threshold status, scoring methodology |

## Where the output differs from the build specification

The specification sketched a structure; the OSCAL schema has the final word. Four changes
were needed:

**1. Identifiers are OSCAL tokens.** `control-id` and `target-id` must match
`^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$` — they must start with a letter or underscore. The NIST
identifiers do not: `3.1.1` starts with a digit, and `3.1.1[d]` also contains brackets.
Emitting them as-is fails validation with one error per identifier (23 errors against the
test environment). They are mapped as follows:

| NIST identifier | OSCAL token |
|---|---|
| requirement `3.1.1` | `sp800-171_3.1.1` |
| objective `3.1.1[d]` | `sp800-171_3.1.1_obj.d` |
| objective `3.5.4` (no letter in 800-171A) | `sp800-171_3.5.4_obj` |

The objective form follows NIST's own OSCAL catalogs, which name 800-53A objectives like
`ac-2_obj.a`. These tokens are this tool's own; they are not taken from a published OSCAL
catalog for 800-171 Rev 2. The original identifiers are preserved in finding titles and in
`control-id` / `objective-id` properties.

**2. Observation methods use the standard vocabulary.** OSCAL's observation methods are the
SP 800-53A assessment methods: `EXAMINE`, `INTERVIEW`, `TEST`, `UNKNOWN`. The specification
suggested `AUTOMATED`, which is how a method was carried out rather than a method. Automated
checks use `TEST` — the tool compares actual configuration against expected, which is what
800-53A calls testing. Requirements needing human review use `EXAMINE`. An
`assessment-mode` property records `automated` or `manual` explicitly.

**3. AWS resources are inventory items.** In OSCAL a subject of type `resource` refers to a
back-matter document, not a cloud asset. IAM users, buckets and security groups are system
assets, so they are declared as `inventory-item`s in the result's `local-definitions`, and
observation subjects reference them by UUID.

**4. Every internal reference resolves.** The JSON schema cannot check that a UUID
reference points at something real, so this is enforced by tests instead: every finding's
`related-observations` resolves, every subject resolves to an inventory item, and the
`import-ap` href resolves to a back-matter resource.

## Deterministic UUIDs

Every UUID is a UUID5, derived rather than random, in two scopes:

- **Run-scoped** — the document, result, observations and findings are derived from a
  fingerprint of the evidence set: the SHA-256 of `manifest.json`. Regenerating from the
  same evidence reproduces them exactly, so regenerating the whole file is byte-identical.
  (`last-modified` is set to the assessment time rather than the write time for the same
  reason.) Two different evidence runs can never share an identifier.
- **Stable** — inventory items are derived from the account and resource ID. The same S3
  bucket gets the same UUID in every assessment, which is what makes two assessments
  comparable resource by resource.

The root namespace is `uuid5(NAMESPACE_URL, "urn:nist171-collector")`. Custom properties
use the namespace `urn:nist171-collector:oscal`, as OSCAL requires for any property name
outside its core vocabulary.

## Validating it

### 1. The test suite (no install needed)

```powershell
pytest tests/test_oscal.py -v
```

`tests/fixtures/oscal/oscal_assessment-results_schema.json` is the official schema, copied
unmodified from the [usnistgov/OSCAL v1.1.3 release](https://github.com/usnistgov/OSCAL/releases/tag/v1.1.3)
(`json/schema/oscal_assessment-results_schema.json`). It is a U.S. Government work. The test
translates the schema's `\p{L}` and `\p{N}` Unicode classes into forms Python's `re` module
supports, then validates generated documents with `jsonschema`.

### 2. compliance-trestle

[compliance-trestle](https://github.com/oscal-compass/compliance-trestle) is IBM's OSCAL
toolkit, now part of the OSCAL Compass project. Its Pydantic models reject documents that
do not fit the OSCAL model.

```powershell
pip install compliance-trestle
python -c "from trestle.oscal.assessment_results import AssessmentResults; ar = AssessmentResults.oscal_read(__import__('pathlib').Path('output/oscal-assessment-results.json')); print('valid:', len(ar.results[0].observations), 'observations')"
```

Checked with compliance-trestle 5.1.0, whose bundled models are OSCAL 1.2.1; it reads this
1.1.3 document without error. Install it in a separate virtual environment if you prefer —
it pulls in a large set of dependencies.

### 3. oscal-cli

NIST's [oscal-cli](https://github.com/metaschema-framework/oscal-cli) is the reference
validator. It is a Java tool, and beyond the JSON schema it checks OSCAL's metaschema
constraints — the allowed values and cross-references that JSON Schema cannot express — so
it is the strictest of the three. The subcommand syntax has changed between releases:
recent versions use `oscal-cli validate <file>`, older ones
`oscal-cli assessment-results validate <file>`. Run `oscal-cli --help` to see which yours
expects.

## Limits

- This describes a **partial** assessment. The result's description carries the scope note,
  unassessed requirements are listed in `remarks`, and `reviewed-controls` never includes a
  requirement that was not assessed.
- There is no OSCAL system security plan or assessment plan behind it, so `import-ap`
  points at a placeholder and the control tokens are local to this tool.
- OSCAL 1.2.x has since been released. This tool targets 1.1.3, which the project scope
  specifies and which remains a published, valid version.
