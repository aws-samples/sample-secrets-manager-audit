# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.3.8] - 2026-04-30

### Added
- Bulk IAM policy loading via `GetAccountAuthorizationDetails` (GAAD). Replaces ~1,000 per-principal API calls with a single paginated call that loads all roles, users, inline policies, managed policies, and trust policies into an in-memory snapshot. Local policy evaluation and principal classification now read from the snapshot instead of making per-principal `GetRolePolicy`, `ListAttachedRolePolicies`, `GetPolicy`, `GetPolicyVersion`, and `GetRole` calls.
- `AccountSnapshot` and `PrincipalSnapshot` data types in `models.py`.
- `load_account_snapshot()` function in `resolver.py` with URL-encoded policy document decoding, managed policy default version resolution, and pagination support.
- `iam:GetAccountAuthorizationDetails` permission added to operator role.
- Graceful fallback: if GAAD is denied, the tool falls back to per-principal policy fetching transparently.

### Changed
- `evaluate_policies_locally()` accepts optional `account_snapshot` parameter — reads from snapshot when available, falls back to per-principal API calls when not.
- `classify_principal()` accepts optional `account_snapshot` parameter — reads trust policy from snapshot when available, falls back to `GetRole` when not.
- Pipeline loads snapshot once after session creation and passes it to both local evaluation and classification.
- Identity Center resolution is now parallelized with up to 4 concurrent workers via `ThreadPoolExecutor`. Credential expiry is handled via a shared abort flag; unresolved roles are marked as partial.
- `SimulatePrincipalPolicy` calls are now parallelized with a bounded thread pool (default 5 workers, tunable via `--max-workers`). For 600 principals at ~250ms latency: ~10s instead of ~3 min.

## [1.3.7] - 2026-04-30

### Added
- Local policy evaluation for fully-denied principals. When the IAM Policy Simulator cannot evaluate a principal's policies (e.g., `secretsmanager:ResourceTag` conditions), the tool now fetches the actual policy documents and evaluates Action, Resource, and Condition blocks client-side. Supports `StringEquals`, `StringEqualsIgnoreCase`, `StringLike`, and their `IfExists` variants.
- 8 new IAM permissions for the operator role to support policy fetching: `ListRolePolicies`, `GetRolePolicy`, `ListAttachedRolePolicies`, `GetPolicy`, `GetPolicyVersion`, `ListUserPolicies`, `GetUserPolicy`, `ListAttachedUserPolicies`.
- `inspect_context_keys` warning is now suppressed for principals the local evaluator successfully resolves. Warnings are only emitted for principals with unsupported condition operators.

### Fixed
- `AccessDenied` error code handling in `_fetch_principal_policies` and `inspect_context_keys`. IAM returns `AccessDenied` (not `AccessDeniedException`) for some operations.

## [1.3.6] - 2026-04-30

### Added
- Simulator limitation warning feature. After simulation, the tool calls `GetContextKeysForPrincipalPolicy` for fully-denied principals to detect policies using `secretsmanager:ResourceTag` conditions the simulator cannot evaluate. Emits per-principal warnings in the report.
- `fully_denied_arns` tracking in `SimulationResult` to identify principals where the simulator returned `implicitDeny` with zero matched statements.
- `iam:GetContextKeysForPrincipalPolicy` permission added to operator role.
- Known Limitations section and FAQ entry in README documenting the IAM Policy Simulator's inability to evaluate service-specific condition keys.

### Fixed
- `SimulatePrincipalPolicy` response parsing now checks `ResourceSpecificResults[].EvalResourceDecision` when the top-level `EvalDecision` is not `allowed`. Policies with scoped `Resource` elements (wildcards, specific ARN patterns) were silently missed.

## [1.3.5] - 2026-03-30

### Added
- `--region` flag for targeting a specific AWS region.
- `--master-profile` flag as a shortcut for Identity Center resolution using a named AWS CLI profile.
- `--last-accessed` flag (opt-in CloudTrail enrichment, previously default-on).
- `--versions` flag for secret version metadata (version IDs, staging labels, creation dates).
- `--quiet` flag to suppress progress messages on stderr.
- `--allow-partial` flag for graceful degradation when cross-account access fails (default is now fail-fast).
- `--ic-region` flag with auto-detection of Identity Center region across common deployment regions.
- `--expiry-warning-minutes` flag for credential expiry warnings before simulation.
- Progress messages on stderr during simulation, IC resolution, and CloudTrail enrichment.
- Early cross-account validation (Step 2b) before the expensive IAM simulation step.
- IC instance caching: `find_ic_instance()` called once and cached, not once per IC role.
- CloudTrail `LookupEvents` queries scoped to target secret via `ResourceName` filter.
- Tag-based policy evaluation via `ContextEntries` with both `aws:ResourceTag` and `secretsmanager:ResourceTag` variants.
- `CustomerStyleTagRole` in CFN test environment for customer-scenario validation.
- Streamlit web UI (`secrets-audit-web`) with browser-based audit interface.
- PDF and CSV output formats.

### Fixed
- IC instance called N times for N roles instead of once (IC instance caching bugfix).
- CloudTrail enrichment hanging on high-volume accounts (switched from account-wide to resource-scoped queries).
- YAML round-trip test failure with NEL/line separator Unicode characters.

## [1.0.0] - 2026-03-15

### Added
- Initial release. Core pipeline: secret resolution, principal enumeration via IAM Policy Simulator, classification (Identity Center, EKS service account, plain IAM), cross-account IC resolution, table/JSON/YAML output.
