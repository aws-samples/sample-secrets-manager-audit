"""Shared audit pipeline for secrets-audit.

Extracts the core audit orchestration from ``cli.py`` into a UI-agnostic
function.  Both the CLI and the Streamlit web UI call ``run_audit()`` to
execute the full pipeline, receiving an ``AuditReport`` on success.

**Security invariant**: this module never calls ``GetSecretValue``.  It only
reads metadata, policies, and Identity Center assignments.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

import botocore.exceptions

from secrets_audit import __version__
from secrets_audit.aws_clients import (
    CrossAccountError,
    ProfileSessionError,
    create_cross_account_session,
    create_prod_session,
    create_profile_session,
    get_caller_identity,
    get_credential_expiry,
    is_expired_token_error,
)
from secrets_audit.classifier import classify_principal, extract_permission_set_name
from secrets_audit.cloudtrail import get_last_accessed
from secrets_audit.identity_center import (
    NoICInstanceError,
    find_ic_instance,
    resolve_identity_center,
)
from secrets_audit.models import (
    AuditReport,
    IdentityCenterResolution,
    PrincipalClassification,
    ReportMetadata,
    SecretVersionInfo,
)
from secrets_audit.resolver import (
    SimulationResult,
    derive_access_level,
    evaluate_policies_locally,
    get_resource_policy_principals,
    inspect_context_keys,
    list_iam_roles,
    list_iam_users,
    list_secret_versions,
    load_account_snapshot,
    resolve_secret,
    simulate_principal_access,
)
from secrets_audit.validators import (
    ACCOUNT_ID_PATTERN,
    PROFILE_NAME_PATTERN,
    REGION_PATTERN,
    ROLE_ARN_PATTERN,
    SECRET_ARN_PATTERN,
    SECRET_NAME_PATTERN,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

ProgressCallback = Callable[[str], None] | None


# ---------------------------------------------------------------------------
# Parameter container
# ---------------------------------------------------------------------------


@dataclass
class AuditParams:
    """All parameters needed to run an audit.

    Fields map 1:1 to CLI options.  Defaults match the CLI defaults.
    """

    secret: str
    output_format: str = "table"
    region: str | None = None
    master_account_id: str | None = None
    cross_account_role_arn: str | None = None
    master_profile: str | None = None
    expand_groups: bool = False
    last_accessed: bool = False
    versions: bool = False
    allow_partial: bool = False
    ic_region: str | None = None
    expiry_warning_minutes: int = 15


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class ValidationError(ValueError):
    """Raised when audit parameters fail validation.

    UI-agnostic — does NOT depend on Click.  Each frontend converts this
    to its own error display (``click.UsageError``, ``st.error()``, etc.).
    """


def validate_params(params: AuditParams) -> None:
    """Validate all fields of *params* before any AWS calls.

    Uses the same compiled regex patterns from ``validators.py`` but raises
    :class:`ValidationError` instead of ``click.BadParameter``.

    Raises
    ------
    ValidationError
        On the first invalid field encountered, or if mutually exclusive
        options are both set.
    """
    # --- secret (required) ---
    if not (SECRET_ARN_PATTERN.match(params.secret) or SECRET_NAME_PATTERN.match(params.secret)):
        raise ValidationError(
            f"Invalid secret identifier: '{params.secret}'. "
            "Must be a valid secret name (alphanumeric, /, _, +, =, ., @, -) "
            "or a full Secrets Manager ARN."
        )

    # --- master_account_id (optional) ---
    if params.master_account_id is not None:
        if not ACCOUNT_ID_PATTERN.match(params.master_account_id):
            raise ValidationError(
                f"Invalid AWS account ID: '{params.master_account_id}'. "
                "Must be a 12-digit numeric string."
            )

    # --- cross_account_role_arn (optional) ---
    if params.cross_account_role_arn is not None:
        if not ROLE_ARN_PATTERN.match(params.cross_account_role_arn):
            raise ValidationError(
                f"Invalid IAM role ARN: '{params.cross_account_role_arn}'. "
                "Expected format: arn:aws:iam::<account-id>:role/<role-name>"
            )

    # --- region (optional) ---
    if params.region is not None:
        if not REGION_PATTERN.match(params.region):
            raise ValidationError(
                f"Invalid AWS region: '{params.region}'. "
                "Expected format: <partition>-<geo>-<number> (e.g. us-east-1, eu-west-2)."
            )

    # --- ic_region (optional) ---
    if params.ic_region is not None:
        if not REGION_PATTERN.match(params.ic_region):
            raise ValidationError(
                f"Invalid AWS region: '{params.ic_region}'. "
                "Expected format: <partition>-<geo>-<number> (e.g. us-east-1, eu-west-2)."
            )

    # --- master_profile (optional) ---
    if params.master_profile is not None:
        if not PROFILE_NAME_PATTERN.match(params.master_profile):
            raise ValidationError(
                f"Invalid profile name: '{params.master_profile}'. "
                "Must contain only alphanumeric characters, underscores, or hyphens."
            )

    # --- Mutual exclusivity ---
    if params.master_profile and (params.master_account_id or params.cross_account_role_arn):
        raise ValidationError(
            "--master-profile is mutually exclusive with "
            "--master-account-id and --cross-account-role-arn."
        )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def run_audit(
    params: AuditParams,
    progress: ProgressCallback = None,
) -> AuditReport:
    """Execute the full audit pipeline and return a report.

    Encapsulates steps 1–9 from the original ``cli.py:main()``.  Raises
    exceptions instead of calling ``sys.exit()`` — each UI handles errors
    its own way.

    Parameters
    ----------
    params:
        Validated audit parameters.
    progress:
        Optional callback for status messages.  The CLI passes a stderr
        writer; the web UI passes a Streamlit status updater.

    Returns
    -------
    AuditReport
        The complete audit report, ready for rendering.

    Raises
    ------
    ValidationError
        If *params* contain invalid values.
    CrossAccountError
        If cross-account assumption fails and ``allow_partial`` is False.
    ProfileSessionError
        If profile session creation fails and ``allow_partial`` is False.
    """
    warnings: list[str] = []

    # --- Step 1: Validate inputs ---
    validate_params(params)

    # --- Step 2: Create production session ---
    prod_session = create_prod_session(region=params.region)

    # --- Step 2b: Early cross-account validation ---
    cross_session = None
    if params.master_profile or (params.master_account_id and params.cross_account_role_arn):
        if progress:
            progress("Validating cross-account access...")

        if params.master_profile:
            try:
                cross_session = create_profile_session(params.master_profile)
                logger.info("Profile session created for %s", params.master_profile)
            except ProfileSessionError as exc:
                if params.allow_partial:
                    msg = (
                        f"Unable to create session from profile {params.master_profile!r}. "
                        f"Displaying permission set name only. "
                        f"Verify profile configuration and credentials."
                    )
                    logger.warning(msg)
                    warnings.append(msg)
                else:
                    raise
        elif params.master_account_id and params.cross_account_role_arn:
            try:
                cross_session = create_cross_account_session(
                    prod_session, params.cross_account_role_arn
                )
                logger.info("Cross-account assumption succeeded")
            except CrossAccountError as exc:
                if params.allow_partial:
                    msg = (
                        f"Unable to assume cross-account role {params.cross_account_role_arn} "
                        f"in master account {params.master_account_id}. "
                        f"Displaying permission set name only. "
                        f"Verify trust policy and permissions."
                    )
                    logger.warning(msg)
                    warnings.append(msg)
                else:
                    raise

    # --- Step 3: Get operator identity ---
    operator_arn = get_caller_identity(prod_session)
    logger.info("Operator identity: %s", operator_arn)

    # --- Step 3b: Load GAAD snapshot ---
    if progress:
        progress("Loading account authorization details...")
    account_snapshot = load_account_snapshot(prod_session, progress=progress)
    if account_snapshot is None:
        warnings.append(
            "GAAD optimization unavailable — falling back to per-principal policy fetching."
        )
    elif progress:
        role_count = sum(1 for v in account_snapshot.values() if "trust_policy" in v)
        user_count = len(account_snapshot) - role_count
        progress(f"Snapshot loaded: {role_count} roles, {user_count} users")

    # --- Step 4: Resolve secret metadata ---
    secret_meta = resolve_secret(prod_session, params.secret)
    logger.info("Resolved secret: %s (%s)", secret_meta.name, secret_meta.arn)  # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure

    # --- Step 4b: Fetch version metadata ---
    secret_versions: list[SecretVersionInfo] = []
    if params.versions:
        if progress:
            progress("Fetching secret version metadata...")
        secret_versions, version_warnings = list_secret_versions(
            prod_session, secret_meta.arn, progress=progress
        )
        warnings.extend(version_warnings)
        if progress:
            progress(f"Version metadata complete: {len(secret_versions)} versions found")

    # --- Step 5: Enumerate principals ---
    # --- Step 4c: Pre-simulation credential expiry check ---
    if params.expiry_warning_minutes > 0:
        try:
            expiry = get_credential_expiry(prod_session)
            if expiry is not None:
                remaining = (expiry - datetime.now(timezone.utc)).total_seconds() / 60
                if remaining < params.expiry_warning_minutes:
                    msg = f"WARNING: Your credentials expire in {int(remaining)} minutes. The audit may not complete."
                    warnings.append(msg)
                    if progress:
                        progress(msg)
        except Exception:
            logger.debug("Could not determine credential expiry", exc_info=True)

    # 5a: Resource-based policy principals
    resource_principals = get_resource_policy_principals(prod_session, secret_meta.arn)

    # 5b: Identity-based policy principals via IAM Policy Simulator
    role_arns = list_iam_roles(prod_session)
    user_arns = list_iam_users(prod_session)
    all_principal_arns = role_arns + user_arns
    logger.info("Simulating access for %d principals...", len(all_principal_arns))

    if progress:
        progress(f"Simulating principals... (0/{len(all_principal_arns)})")

    sim_result = simulate_principal_access(
        prod_session, all_principal_arns, secret_meta.arn, progress=progress,
        resource_tags=secret_meta.tags,
    )
    identity_principals = sim_result.principals

    if sim_result.truncated:
        msg = (f"WARNING: Credentials expired during IAM simulation. "
               f"Report is incomplete ({sim_result.evaluated_count} of {sim_result.total_count} principals evaluated).")
        warnings.append(msg)
        if progress:
            progress(msg)

    if progress:
        progress(
            f"Simulation complete: {len(identity_principals)} of "
            f"{len(all_principal_arns)} principals have access"
        )

    # --- Step 5c: Local policy evaluation for fully-denied principals ---
    local_principals: list = []
    if not sim_result.truncated and sim_result.fully_denied_arns:
        sim_found_arns = frozenset(p.principal_arn for p in identity_principals)
        if progress:
            progress(
                f"Evaluating policies locally for {len(sim_result.fully_denied_arns)} "
                f"fully-denied principal(s)..."
            )
        local_result = evaluate_policies_locally(
            prod_session,
            sim_result.fully_denied_arns,
            secret_meta.arn,
            secret_tags=secret_meta.tags,
            skip_arns=sim_found_arns,
            progress=progress,
            account_snapshot=account_snapshot,
        )
        local_principals = local_result.principals

        if local_result.truncated:
            msg = (
                f"WARNING: Credentials expired during local policy evaluation. "
                f"Local evaluation is incomplete ({local_result.evaluated_count} of "
                f"{local_result.total_count} principals evaluated)."
            )
            warnings.append(msg)
            if progress:
                progress(msg)

        if progress:
            progress(
                f"Local evaluation complete: {len(local_principals)} additional "
                f"principal(s) found"
            )

    # --- Step 5d: Inspect context keys for remaining fully-denied principals ---
    local_found_arns = frozenset(p.principal_arn for p in local_principals)
    remaining_denied = [
        arn for arn in sim_result.fully_denied_arns
        if arn not in local_found_arns
    ]
    if remaining_denied and not sim_result.truncated:
        if progress:
            progress(
                f"Inspecting context keys for {len(remaining_denied)} "
                f"fully-denied principal(s)..."
            )
        flagged_warnings, inspection_warnings = inspect_context_keys(
            prod_session, remaining_denied, progress=progress
        )
        warnings.extend(flagged_warnings)
        warnings.extend(inspection_warnings)

    # Merge: deduplicate by ARN, prefer identity_policy source
    principals_by_arn = {p.principal_arn: p for p in resource_principals}
    for p in identity_principals:
        if p.principal_arn in principals_by_arn:
            principals_by_arn[p.principal_arn].policy_source = "both"
        else:
            principals_by_arn[p.principal_arn] = p

    # Merge local evaluation results
    for p in local_principals:
        if p.principal_arn in principals_by_arn:
            existing = principals_by_arn[p.principal_arn]
            merged_actions = list(set(existing.allowed_actions) | set(p.allowed_actions))
            existing.allowed_actions = merged_actions
            existing.access_level = derive_access_level(merged_actions)
            if existing.policy_source == "resource_policy":
                existing.policy_source = "both"
        else:
            principals_by_arn[p.principal_arn] = p

    principals = list(principals_by_arn.values())

    # --- Step 6: Classify each principal ---
    for i, p in enumerate(principals):
        principals[i] = classify_principal(prod_session, p, account_snapshot=account_snapshot)

    # --- Step 7: Identity Center resolution ---
    target_account_id = secret_meta.arn.split(":")[4]

    ic_roles = [
        (i, p)
        for i, p in enumerate(principals)
        if p.classification == PrincipalClassification.IDENTITY_CENTER
        and extract_permission_set_name(p.principal_name) is not None
    ]

    if progress and ic_roles and params.ic_region is None:
        progress("Detecting Identity Center region...")

    if progress and ic_roles:
        progress(f"Resolving {len(ic_roles)} Identity Center role(s)...")

    # Pre-resolve IC instance once before the loop
    ic_instance_found = False
    cached_instance_arn: str | None = None
    cached_identity_store_id: str | None = None
    effective_ic_region: str | None = params.ic_region

    if cross_session is not None and ic_roles:
        try:
            cached_instance_arn, cached_identity_store_id, detected_region = find_ic_instance(
                cross_session, ic_region=params.ic_region
            )
            effective_ic_region = params.ic_region if params.ic_region is not None else detected_region
            ic_instance_found = True
        except (NoICInstanceError, botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            msg = f"No Identity Center instance found: {exc}"
            warnings.append(msg)
            for _, p in ic_roles:
                ps_name = extract_permission_set_name(p.principal_name)
                p.ic_resolution = IdentityCenterResolution(
                    permission_set_name=ps_name, partial=True
                )

    if ic_instance_found:
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed

        abort = threading.Event()

        def _resolve_one(role_idx: int, idx: int, principal: object) -> tuple[int, int, object | None]:
            if abort.is_set():
                return role_idx, idx, None
            ps_name = extract_permission_set_name(principal.principal_name)
            try:
                resolution = resolve_identity_center(
                    cross_session, ps_name, target_account_id, params.expand_groups,
                    ic_region=effective_ic_region,
                    instance_arn=cached_instance_arn,
                    identity_store_id=cached_identity_store_id,
                )
                return role_idx, idx, resolution
            except botocore.exceptions.ClientError as exc:
                if is_expired_token_error(exc):
                    abort.set()
                    return role_idx, idx, "EXPIRED"
                raise

        with ThreadPoolExecutor(max_workers=min(4, len(ic_roles))) as executor:
            futures = {
                executor.submit(_resolve_one, role_idx, i, p): (role_idx, i, p)
                for role_idx, (i, p) in enumerate(ic_roles)
            }
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if progress:
                    progress(f"Resolving Identity Center roles... ({completed}/{len(ic_roles)})")
                role_idx, i, p = futures[future]
                try:
                    _, _, resolution = future.result()
                except Exception:
                    raise
                if resolution == "EXPIRED":
                    remaining_count = len(ic_roles) - completed
                    msg = f"WARNING: Credentials expired during Identity Center resolution. IC data is incomplete for {remaining_count} remaining role(s)."
                    warnings.append(msg)
                    if progress:
                        progress(msg)
                    break
                elif resolution is not None:
                    p.ic_resolution = resolution

        # Mark any unresolved roles as partial (aborted or skipped)
        for _, p in ic_roles:
            if p.ic_resolution is None:
                ps_name = extract_permission_set_name(p.principal_name)
                p.ic_resolution = IdentityCenterResolution(permission_set_name=ps_name, partial=True)
    elif cross_session is None:
        for role_idx, (i, p) in enumerate(ic_roles):
            if progress:
                progress(f"Resolving Identity Center role {role_idx + 1} of {len(ic_roles)}...")

            ps_name = extract_permission_set_name(p.principal_name)
            p.ic_resolution = IdentityCenterResolution(
                permission_set_name=ps_name, partial=True
            )

    # --- Step 8: CloudTrail enrichment ---
    if params.last_accessed:
        principal_arns = [p.principal_arn for p in principals]
        if progress:
            progress("Starting CloudTrail enrichment...")
        try:
            last_accessed_map = get_last_accessed(
                prod_session, secret_meta.arn, principal_arns, progress=progress
            )
            if progress:
                progress("CloudTrail enrichment complete.")
            for p in principals:
                p.last_accessed = last_accessed_map.get(p.principal_arn)
        except botocore.exceptions.ClientError as exc:
            if is_expired_token_error(exc):
                from secrets_audit.cloudtrail import CREDENTIALS_EXPIRED
                msg = "WARNING: Credentials expired during CloudTrail enrichment. Last-accessed data is unavailable."
                warnings.append(msg)
                if progress:
                    progress(msg)
                for p in principals:
                    p.last_accessed = CREDENTIALS_EXPIRED
            else:
                raise

    # --- Step 9: Build report ---
    metadata = ReportMetadata(
        secret_name=secret_meta.name,
        secret_arn=secret_meta.arn,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=operator_arn,
        tool_version=f"secrets-audit v{__version__}",
        region=prod_session.region_name,
    )
    report = AuditReport(
        metadata=metadata,
        principals=principals,
        warnings=warnings,
        versions=secret_versions,
    )

    return report
