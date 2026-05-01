# secrets-audit

Resolve and report **who** can access your AWS Secrets Manager secrets — across accounts, through Identity Center, and down to the human behind the IAM role.

## The Problem

AWS Secrets Manager makes it easy to store secrets, but answering "who can actually read this secret?" is hard:

- **IAM policies are scattered.** Access can come from identity-based policies attached to users/roles, resource-based policies on the secret itself, or permission boundaries. There's no single API that gives you the full picture.
- **Identity Center adds a layer of indirection.** In organizations using AWS IAM Identity Center (IC, formerly SSO), the IAM roles in your workload accounts are auto-generated names like `AWSReservedSSO_ReadOnlyAccess_abcdef123456`. To know which *humans* have access, you need to resolve those roles back through permission sets, account assignments, users, and groups, which live in a completely different account.
- **EKS service accounts blur the line further.** Pods running in EKS assume IAM roles via OIDC federation. The trust policy tells you it's an EKS workload, but that's not obvious from the role name alone.
- **Secrets Manager records a "last accessed" timestamp, but it does not identify which principal performed the access** and you must query CloudTrail to obtain per-principal access details.

`secrets-audit` solves all of this in a single command.

## Quick Start

```bash
git clone git@ssh.gitlab.aws.dev:rayelkin/secrets-audit.git
cd secrets-audit
pip install .
secrets-audit --secret <your-secret-name-or-arn>
```

## What It Does

```
secrets-audit --secret <your-secret-name-or-arn> --output table
```

The tool runs a 10-step pipeline:

1. **Validate inputs** — secret name/ARN format, account IDs, role ARNs
2. **Create AWS session** — uses your current credentials (no long-lived keys)
3. **Identify the operator** — records who ran the audit via `sts:GetCallerIdentity`
4. **Resolve secret metadata** — calls `DescribeSecret` (never `GetSecretValue`)
5. **Enumerate principals** — Lists all IAM roles and users. Loads all IAM policy data in bulk via `GetAccountAuthorizationDetails` (one paginated call instead of per-principal API fan-out). Simulates access for each principal using the IAM Policy Simulator with `GetSecretValue`, `PutSecretValue`, `UpdateSecret`, `DeleteSecret`, `CreateSecret`, and `DescribeSecret` actions, passing the secret's resource tags as context so tag-based policy conditions evaluate correctly. Parses the secret's resource-based policy for additional Allow grants. For principals the simulator fully denied with no matched statements, evaluates their pre-loaded IAM policies locally to detect access the simulator cannot (e.g., `secretsmanager:ResourceTag` conditions). For any remaining unresolved principals, inspects their policy context keys via `GetContextKeysForPrincipalPolicy` and warns if they reference conditions the local evaluator couldn't handle.
6. **Classify each principal** — inspects trust policies to categorize as Identity Center-managed, EKS service account, or plain IAM
7. **Resolve Identity Center** — assumes a cross-account role into the management account to map permission sets → account assignments → users and groups
8. **Enrich with CloudTrail** *(only when `--last-accessed` is provided)* — queries `LookupEvents` for `GetSecretValue` calls to show when each principal last accessed the secret
9. **Build the report** — assembles metadata, principals, and warnings into a structured report
10. **Render output** — formats as table, JSON, CSV, or PDF

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Workload Account                       │
│                                                          │
│  ┌──────────────┐  ┌─────────┐  ┌───────────────────┐  │
│  │ Secrets Mgr  │  │   IAM   │  │    CloudTrail     │  │
│  │DescribeSecret│  │ListRoles│  │  LookupEvents     │  │
│  │GetResourcePol│  │GetRole  │  │  (GetSecretValue) │  │
│  └──────────────┘  │Simulate │  └───────────────────┘  │
│                     └─────────┘                          │
└──────────────────────┬──────────────────────────────────┘
                       │ sts:AssumeRole
                       ▼
┌─────────────────────────────────────────────────────────┐
│                 Management Account                       │
│                                                          │
│  ┌──────────────────┐  ┌────────────────────────────┐   │
│  │   SSO Admin       │  │    Identity Store          │   │
│  │ ListInstances     │  │ DescribeUser               │   │
│  │ ListPermissionSets│  │ DescribeGroup              │   │
│  │ ListAccountAssign │  │ ListGroupMemberships       │   │
│  └──────────────────┘  └────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

The tool is **read-only by design**. It never modifies IAM policies, secret values, or Identity Center assignments.

## Prerequisites

- Python 3.11 or later
- AWS credentials that you have configured via `aws login` (for IAM Identity Center), environment variables, or an instance profile. The tool uses your current session and does not prompt for credentials.
- For Identity Center resolution: a cross-account IAM role in the management account (see [Required IAM Permissions](#required-iam-permissions) below)

## Installation

Requires Python 3.11+.

```bash
# From source
pip install .

# For development (includes test dependencies)
pip install -e ".[test]"
```

## Dependencies

Runtime (pinned in `pyproject.toml`):

| Package | Version | Purpose |
|---|---|---|
| `boto3` | 1.38.15 | AWS SDK — all API calls to Secrets Manager, IAM, STS, Identity Center, CloudTrail |
| `click` | 8.1.8 | CLI framework — argument parsing, help text, exit codes |
| `reportlab` | 4.4.10 | PDF report generation |

Optional (web UI):

| Package | Version | Purpose |
|---|---|---|
| `streamlit` | >=1.45.0 | Web UI framework — browser-based audit interface (`pip install secrets-audit[web]`) |

Test:

| Package | Version | Purpose |
|---|---|---|
| `pytest` | 8.3.5 | Test runner |
| `hypothesis` | 6.122.3 | Property-based testing for validators, classifiers, and renderers |
| `moto` | 5.1.3 | AWS API mocking for integration tests |
| `pytest-cov` | 6.1.1 | Coverage reporting |

No dependencies make outbound network calls beyond AWS API endpoints.

## Usage

### Basic (single account, table output)

```bash
secrets-audit --secret <your-secret-name-or-arn>
```

### Targeting a specific region

```bash
# Audit a secret by name in us-west-2 (no need for the full ARN)
secrets-audit --secret rds/prod-db-west/app_user --region us-west-2
```

### With Identity Center resolution

There are two ways to provide management account access for Identity Center resolution:

```bash
# Option A: Named AWS CLI profile (recommended if you have one configured)
secrets-audit --secret <your-secret-name-or-arn> \
  --master-profile management-account \
  --expand-groups

# Option B: Explicit account ID and role ARN
secrets-audit --secret <your-secret-name-or-arn> \
  --region us-west-2 \
  --master-account-id <MANAGEMENT_ACCOUNT_ID> \
  --cross-account-role-arn arn:aws:iam::<MANAGEMENT_ACCOUNT_ID>:role/SecretsAuditReadOnly \
  --expand-groups
```

### Including last-accessed timestamps from CloudTrail

```bash
# Include last-accessed timestamps from CloudTrail (slower on high-volume accounts)
secrets-audit --secret my/secret --last-accessed --output table
```

### Suppressing progress messages

```bash
# Suppress progress messages for scripted/automated use
secrets-audit --secret my/secret --quiet --output json > report.json
```

### Including secret version metadata

```bash
# Include version IDs, staging labels, and creation dates in the report
secrets-audit --secret my/secret --versions --output table
```

### Output formats

```bash
# JSON (machine-readable, full detail)
secrets-audit --secret my/secret --output json

# CSV (spreadsheet-friendly, includes IC group member rows)
secrets-audit --secret my/secret --output csv

# PDF (formatted for print/audit submission)
secrets-audit --secret my/secret --output pdf

# Write to file instead of stdout
secrets-audit --secret my/secret --output json --output-file report.json
secrets-audit --secret my/secret --output csv --output-file report.csv
secrets-audit --secret my/secret --output pdf --output-file audit-report.pdf
```

### Using a secret ARN instead of name

```bash
secrets-audit --secret arn:aws:secretsmanager:us-east-1:111122223333:secret:rds/prod-db-west/app_user-AbCdEf
```

### CLI reference

| Option | Required | Default | Description |
|---|---|---|---|
| `--secret` | Yes | — | Secret name or full ARN. Names follow hierarchical paths (e.g. `service/environment/name`) |
| `--output` | No | `table` | Output format: `table`, `json`, `csv`, or `pdf` |
| `--region` | No | — | AWS region for the audit session (e.g. `us-west-2`). Defaults to the environment's configured region. Useful when auditing secrets by name in a non-default region. |
| `--master-account-id` | No | — | 12-digit AWS management account ID for Identity Center resolution |
| `--cross-account-role-arn` | No | — | IAM role ARN to assume in the management account |
| `--master-profile` | No | — | Named AWS CLI profile for management account access. Mutually exclusive with `--master-account-id` and `--cross-account-role-arn`. |
| `--last-accessed` | No | `false` | Enable CloudTrail last-accessed enrichment. Queries CloudTrail for GetSecretValue events to show when each principal last accessed the secret. May significantly increase execution time on accounts with high event volume. |
| `--versions` | No | `false` | Include secret version metadata (version IDs, staging labels, creation dates) in the report. Calls `ListSecretVersionIds` (read-only, no secret values). |
| `--expand-groups` | No | `false` | Expand Identity Center group memberships to individual users |
| `--quiet` | No | `false` | Suppress progress messages written to stderr during long-running steps. Useful for scripted or automated use. |
| `--allow-partial` | No | `false` | Continue with a partial report when cross-account access fails. Without this flag, the tool exits immediately on cross-account failure. Only applies when `--master-account-id`/`--cross-account-role-arn` or `--master-profile` is provided. |
| `--ic-region` | No | — | AWS region for Identity Center API calls (e.g. `us-east-1`). Optional: the tool auto-detects the IC region by trying common regions when omitted. Only applies when cross-account flags are provided. |
| `--output-file` | No | — | Write report to file instead of stdout |
| `--expiry-warning-minutes` | No | `15` | Minutes before credential expiry to warn. Set to 0 to disable. If credentials are near expiry, a warning is emitted before the simulation step. If credentials expire mid-run, the tool produces a partial report instead of crashing. |
| `--max-workers` | No | `5` | Maximum concurrent `SimulatePrincipalPolicy` calls. Higher values speed up large accounts but increase throttling pressure. The adaptive retry config handles throttling automatically. |

For Identity Center resolution, use either `--master-profile` or the `--master-account-id` / `--cross-account-role-arn` pair, not both. If none are provided, the tool still reports all principals but cannot resolve IC role names to human users.

When `--region` is provided alongside a full ARN for `--secret`, the ARN's embedded region takes precedence for Secrets Manager calls. No conflict, no error.

## Required IAM Permissions

### Workload account (where the secret lives)

The operator's IAM identity needs these read-only permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecretsAuditWorkloadAccount",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecretVersionIds",
        "iam:ListRoles",
        "iam:ListUsers",
        "iam:GetRole",
        "iam:SimulatePrincipalPolicy",
        "iam:GetContextKeysForPrincipalPolicy",
        "iam:GetAccountAuthorizationDetails",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListAttachedUserPolicies",
        "sts:GetCallerIdentity",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Note:** `iam:SimulatePrincipalPolicy` is rate-limited to ~5 requests per second. The tool parallelizes these calls (default 5 workers, tunable via `--max-workers`) and uses adaptive retry for throttling. `iam:GetAccountAuthorizationDetails` loads all IAM policy data in a single paginated call, eliminating per-principal API fan-out. The remaining per-principal permissions (`ListRolePolicies`, `GetRolePolicy`, etc.) are retained as a fallback if `GetAccountAuthorizationDetails` is denied.

### Management account (for Identity Center resolution)

Create a cross-account role with this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecretsAuditIdentityCenterReadOnly",
      "Effect": "Allow",
      "Action": [
        "sso:ListInstances",
        "sso:ListPermissionSets",
        "sso:DescribePermissionSet",
        "sso:ListAccountAssignments",
        "identitystore:DescribeUser",
        "identitystore:DescribeGroup",
        "identitystore:ListGroupMemberships"
      ],
      "Resource": "*"
    }
  ]
}
```

And a trust policy allowing the workload account to assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<WORKLOAD_ACCOUNT_ID>:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Security Model

| Guarantee | How it's enforced |
|---|---|
| Never reads secret values | The tool calls `DescribeSecret`, `GetResourcePolicy`, and `ListSecretVersionIds` only. `GetSecretValue` is never imported or called. |
| No credential persistence | Cross-account credentials are held in memory only. No files are written. |
| No mutations | The tool only calls read/list/describe/simulate APIs. It never creates, updates, or deletes any AWS resource. |
| Input validation | All CLI inputs (secret name, ARN, account ID, role ARN, region, profile name) are validated against regex patterns before any API call. |
| Output safety | Rendered output never contains secret values, full policy JSON, or raw STS credentials. Only the derived access level is shown. |

## Graceful Degradation

The tool is designed to produce the best report it can, even when some data sources are unavailable:

| Scenario | Behavior |
|---|---|
| Cross-account role assumption fails | By default, the tool exits immediately with a clear error before any expensive pipeline steps run. Use `--allow-partial` to continue with a partial report instead: IC-managed roles show the permission set name but not resolved users/groups, and a warning is included. |
| Master profile credentials fail | Same behavior as cross-account failure: fail-fast by default, partial report with `--allow-partial`. |
| CloudTrail access denied | All `last_accessed` fields show "Unknown (CloudTrail unavailable)". The rest of the report is complete. |
| Version metadata access denied | When `--versions` is used but `ListSecretVersionIds` is denied, the versions section is omitted and a warning is included. The rest of the report is complete. |
| Individual IC user deleted | Shows "User ID: [id] (deleted)" instead of the display name. |
| No principals have access | Outputs "No IAM principals have access to this secret" with full metadata header. |
| Credentials expire mid-run | The tool produces a partial report with whatever data was collected before expiry. Warnings indicate which phase was interrupted and how many principals were evaluated. Use `--expiry-warning-minutes` to get an early warning before the simulation step. |
| Context key inspection denied | When `GetContextKeysForPrincipalPolicy` is denied for a principal, the tool skips that principal and continues inspecting others. If denied for all principals (e.g., the operator role lacks the permission), the tool completes normally without limitation warnings — the rest of the report is unaffected. |
| Policy fetching denied | When local policy evaluation cannot fetch policies for a principal (e.g., `ListRolePolicies` denied for AWS service-linked roles), the tool skips that principal and continues. A warning is logged but the report is unaffected. |

## Output Examples

The examples below show a full-featured invocation with Identity Center resolution and version metadata:

```bash
secrets-audit --secret rds/prod-db-west/app_user \
  --region us-east-1 \
  --master-account-id 999988887777 \
  --cross-account-role-arn arn:aws:iam::999988887777:role/SecretsAuditReadOnly \
  --versions --last-accessed --expand-groups --output table
```

### Table

```
Secret: rds/prod-db-west/app_user
ARN:    arn:aws:secretsmanager:us-east-1:111122223333:secret:rds/prod-db-west/app_user-AbCdEf
Region: us-east-1
Report generated: 2026-03-21T12:00:00+00:00
Generated by:     arn:aws:iam::111122223333:role/SecurityAuditor
Tool:             secrets-audit v1.3.3

PRINCIPAL TYPE   PRINCIPAL NAME                                         IC USER / GROUP                          ACCESS LEVEL   LAST ACCESSED
--------------   ----------------------------------------------------   --------------------------------------   ------------   ---------------------------
IAM Role         AWSReservedSSO_ReadOnlyAccess_abcdef123456             jane@example.com                         Read           2026-03-15 09:30 UTC
IAM Role         AWSReservedSSO_DatabaseAdmin_789abc012345              Group: DBA-Team                          Read/Write     2026-03-20 14:22 UTC
                                                                        alice@example.com (Enabled)
                                                                        bob@example.com (Enabled)
IAM Role         eks-pod-role                                           Service Account (EKS)                    Read/Write     No recent access (>90 days)
IAM User         deploy-bot                                             N/A                                      Admin          2026-03-18 08:15 UTC

SECRET VERSIONS
VERSION ID                               STAGING LABELS              CREATED DATE
--------------------------------------   -------------------------   ---------------------------
a1b2c3d4-5678-90ab-cdef-EXAMPLE11111    AWSCURRENT                  2026-03-10 06:00 UTC
a1b2c3d4-5678-90ab-cdef-EXAMPLE22222    AWSPREVIOUS                 2026-02-15 12:30 UTC
```

### JSON (abbreviated)

```json
{
  "secret_name": "rds/prod-db-west/app_user",
  "secret_arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:rds/prod-db-west/app_user-AbCdEf",
  "region": "us-east-1",
  "generated_at": "2026-03-21T12:00:00+00:00",
  "generated_by": "arn:aws:iam::111122223333:role/SecurityAuditor",
  "tool_version": "secrets-audit v1.0.0",
  "warnings": [],
  "principals": [
    {
      "principal_type": "IAM Role",
      "principal_name": "AWSReservedSSO_ReadOnlyAccess_abcdef123456",
      "access_level": "Read",
      "last_accessed": "2026-03-15T09:30:00+00:00",
      "policy_source": "identity",
      "is_service_account": false,
      "service_account_detail": null,
      "permission_set_name": "ReadOnlyAccess",
      "identity_center_user": [
        {"user_id": "90678012-abcd-1234-efgh-111122223333", "display_name": "Jane Smith", "email": "[email]", "deleted": false}
      ],
      "identity_center_group": null,
      "ic_partial": false
    },
    {
      "principal_type": "IAM Role",
      "principal_name": "AWSReservedSSO_DatabaseAdmin_789abc012345",
      "access_level": "Read/Write",
      "last_accessed": "2026-03-20T14:22:00+00:00",
      "policy_source": "identity",
      "is_service_account": false,
      "service_account_detail": null,
      "permission_set_name": "DatabaseAdmin",
      "identity_center_user": null,
      "identity_center_group": [
        {
          "group_id": "g-abcdef1234",
          "group_name": "DBA-Team",
          "total_member_count": 2,
          "members": [
            {"user_id": "90678012-abcd-1234-efgh-444455556666", "display_name": "Alice Nguyen", "email": "[email]", "deleted": false},
            {"user_id": "90678012-abcd-1234-efgh-777788889999", "display_name": "Bob Chen", "email": "[email]", "deleted": false}
          ]
        }
      ],
      "ic_partial": false
    },
    {
      "principal_type": "IAM Role",
      "principal_name": "eks-pod-role",
      "access_level": "Read/Write",
      "last_accessed": null,
      "policy_source": "identity",
      "is_service_account": true,
      "service_account_detail": "EKS OIDC",
      "identity_center_user": null,
      "identity_center_group": null
    }
  ],
  "versions": [
    {"version_id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111", "staging_labels": ["AWSCURRENT"], "created_date": "2026-03-10T06:00:00+00:00"},
    {"version_id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE22222", "staging_labels": ["AWSPREVIOUS"], "created_date": "2026-02-15T12:30:00+00:00"}
  ]
}
```


## Project Structure

```
secrets_audit/
├── __init__.py          # Package version
├── __main__.py          # python -m secrets_audit entry point
├── aws_clients.py       # Session factory, cross-account AssumeRole, caller identity
├── classifier.py        # Trust policy inspection → IC / EKS / plain IAM classification
├── cli.py               # Click CLI definition and 10-step pipeline orchestration
├── cloudtrail.py        # LookupEvents query for last-accessed timestamps
├── identity_center.py   # Cross-account IC resolution (permission sets → users/groups)
├── models.py            # Dataclasses and enums (SecretMetadata, PrincipalAccess, AuditReport, etc.)
├── pipeline.py          # Shared audit pipeline — run_audit() called by both CLI and web UI
├── renderer.py          # Table, JSON, CSV, and PDF output formatters
├── resolver.py          # DescribeSecret, IAM Policy Simulator, resource policy parsing
├── validators.py        # Input validation (secret name/ARN, account ID, role ARN, region, profile name)
└── web.py               # Streamlit web UI — browser-based audit interface (optional dependency)
```

## Development

> **Note:** The test suite (358 tests: unit, property-based, and integration) is maintained in a private development repository and is not included in this distribution.

```bash
# Install with test dependencies
pip install -e ".[test]"

# Run all tests (328 tests: unit, property-based, and integration)
pytest

# Run with coverage
pytest --cov=secrets_audit

# Run a specific test file
pytest tests/test_integration.py -v

# Run only property-based tests
pytest -k "hypothesis" -v
```

## Known Limitations

| Limitation | Impact | Workaround |
|---|---|---|
| IAM Policy Simulator cannot evaluate service-specific condition keys | Policies using `secretsmanager:ResourceTag/<key>` (or other service-specific tag condition keys) in their `Condition` block are not evaluated by the simulator. The tool compensates with local policy evaluation that fetches and parses the actual policy documents client-side, detecting access for `StringEquals`, `StringEqualsIgnoreCase`, `StringLike`, and their `IfExists` variants. For unsupported condition operators or non-tag condition keys, a warning is emitted instead. See [IAM policy simulator documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html). | No action needed for supported condition operators. For unsupported operators, rewrite policies to use `aws:ResourceTag/<key>` instead of `secretsmanager:ResourceTag/<key>`. |
| IAM Policy Simulator rate limit | `SimulatePrincipalPolicy` is limited to ~5 requests per second. The tool parallelizes calls (default 5 workers, tunable via `--max-workers`) and uses adaptive retry. An account with 600 roles completes in about 30 seconds. | Use `--max-workers` to tune concurrency for your account's rate limits. |

## FAQ

**Does this tool read my secret values?**
No. The tool calls `DescribeSecret` and `GetResourcePolicy` only. It never calls `GetSecretValue`. The import doesn't even exist in the codebase. It only needs metadata, policies, and Identity Center assignments to build the access report.

**Why does the report take so long on large accounts?**
The primary bottleneck is the IAM Policy Simulator API (`SimulatePrincipalPolicy`), which is rate-limited to ~5 requests per second. The tool parallelizes these calls with a bounded thread pool (default 5 workers, tunable via `--max-workers`). An account with 600 roles completes simulation in about 30 seconds instead of 3 minutes. Identity Center resolution is also parallelized (4 concurrent workers). IAM policy data is loaded in bulk via `GetAccountAuthorizationDetails` (one paginated call instead of per-principal fan-out). Progress messages appear on stderr so you know the tool is working. Use `--quiet` to suppress them in scripts. CloudTrail enrichment (`--last-accessed`) is opt-in and adds 3-10 seconds for most secrets.

**What happens if I don't have cross-account access to the management account?**
If you provided cross-account flags (`--master-account-id`/`--cross-account-role-arn` or `--master-profile`) and the credentials are wrong, the tool exits immediately with a clear error before running the expensive IAM Policy Simulator step. The error message tells you what went wrong and suggests `--allow-partial` if you want a partial report anyway. With `--allow-partial`, the tool continues and produces a complete report of all principals with access levels and classifications, but IC-managed roles show the permission set name (e.g. `PS: ReadOnlyAccess`) instead of resolved user names. If you don't provide any cross-account flags at all, the tool runs normally without IC resolution.

**Can I audit multiple secrets at once?**
Not in a single invocation. The tool audits one secret per run. For bulk audits, script it:
```bash
for secret in rds/prod-db-west/app_user saas/datadog/api-key snowflake/prod/etl_user; do
  secrets-audit --secret "$secret" --output json --output-file "${secret//\//-}.json"
done
```

**Why do some IAM roles show up that I don't recognize?**
The Policy Simulator evaluates every IAM role in the account, including AWS service-linked roles, SSO-provisioned roles, and roles created by other teams or automation. If a role has a policy that grants `secretsmanager:*` or broad resource access (`Resource: "*"`), it will appear in the report. This is intentional. Auditors need the complete picture, not just the roles you expect.

**How does `--region` interact with a full secret ARN?**
They coexist without conflict. When you pass both `--region us-west-2` and `--secret arn:aws:secretsmanager:us-east-1:...`, the session is created in `us-west-2` but `DescribeSecret` routes to `us-east-1` because the ARN is authoritative. The report metadata will show the session region. In practice, if you're using a full ARN you don't need `--region`. It's most useful when referring to secrets by name.

**When should I use `--master-profile` vs `--master-account-id` / `--cross-account-role-arn`?**
Use `--master-profile` if you already have a named profile in `~/.aws/config` for your management account (e.g. with `role_arn` and `source_profile` configured). It saves keystrokes and avoids hardcoding ARNs in your commands. Use the explicit `--master-account-id` + `--cross-account-role-arn` pair if you don't have a profile set up, or if you're scripting and want the role ARN to be visible in the command. The two approaches are mutually exclusive. The tool will error if you mix them.

**What if my Identity Center is in a different region than my profile default?**
The tool auto-detects the IC region. It tries your session's default region first, then checks common IC deployment regions (us-east-1, us-west-2, eu-west-1, eu-central-1, ap-southeast-1) until it finds the instance. You don't need to know which region IC is in. If auto-detection is too slow or you want to skip the extra API calls, use `--ic-region us-east-1` (or whichever region your IC is in) to target it directly.

**How does the tool handle `secretsmanager:ResourceTag` conditions?**
The IAM Policy Simulator cannot evaluate service-specific condition keys like `secretsmanager:ResourceTag/<key>`. The tool compensates with local policy evaluation: it fetches the actual policy documents and evaluates Action, Resource, and Condition blocks client-side. This covers `StringEquals`, `StringEqualsIgnoreCase`, `StringLike`, and their `IfExists` variants. For condition operators the local evaluator doesn't support, a warning is emitted identifying the principal and recommending the use of `aws:ResourceTag/<key>` instead, which both the simulator and the local evaluator handle correctly. See [IAM policy simulator documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html) for background on the simulator limitation.

## Web UI

The tool includes an optional browser-based interface powered by Streamlit. It runs on your local machine using your existing AWS credentials and connects only to AWS API endpoints. No data is sent to third-party services.

### Installation

```bash
pip install secrets-audit[web]
```

### Launch

```bash
secrets-audit-web
```

This starts a local Streamlit server on `http://localhost:8501` and opens your browser. The sidebar provides the same options as the CLI: secret name/ARN, region, Identity Center configuration, CloudTrail enrichment, version metadata, and output format.

Results display as an interactive table you can sort and browse. Download buttons let you save the report as PDF or CSV directly from the browser.

The web UI binds to localhost only and makes no network calls beyond AWS API endpoints.

## Versioning

This project follows [Semantic Versioning](https://semver.org/). The version is defined in `pyproject.toml` and `secrets_audit/__init__.py`. It appears in every report header as `Tool: secrets-audit v1.3.8`.

## License

MIT. See [LICENSE](LICENSE).
