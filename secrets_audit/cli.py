"""CLI entry point and pipeline orchestrator for secrets-audit.

Wires the full pipeline: validate → create session → get operator identity →
resolve secret → enumerate principals → classify → IC resolve → CloudTrail
enrich → build AuditReport → render → write output.

**Security invariant**: this module never calls ``GetSecretValue``.  It only
reads metadata, policies, and Identity Center assignments.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import botocore.exceptions
import click

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
from secrets_audit.pipeline import AuditParams, ValidationError, validate_params
from secrets_audit.renderer import render
from secrets_audit.resolver import (
    SimulationResult,
    derive_access_level,
    evaluate_policies_locally,
    get_resource_policy_principals,
    inspect_context_keys,
    list_iam_roles,
    list_iam_users,
    list_secret_versions,
    resolve_secret,
    simulate_principal_access,
)
from secrets_audit.validators import (
    validate_account_id,
    validate_profile_name,
    validate_region,
    validate_role_arn,
    validate_secret_input,
)

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str], None] | None


@click.command()
@click.version_option(version=__version__, prog_name="secrets-audit")
@click.option("--secret", required=True, help="Secret name or ARN")
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["table", "json", "csv", "pdf"]),
    default="table",
    help="Output format (default: table)",
)
@click.option(
    "--master-account-id",
    default=None,
    help="12-digit master account ID for Identity Center resolution",
)
@click.option(
    "--cross-account-role-arn",
    default=None,
    help="IAM role ARN for cross-account assumption into master account",
)
@click.option(
    "--expand-groups",
    is_flag=True,
    default=False,
    help="Expand IC group memberships to individual users",
)
@click.option(
    "--output-file",
    default=None,
    type=click.Path(),
    help="Write report to file instead of stdout",
)
@click.option(
    "--region",
    default=None,
    help="AWS region for the audit session (e.g. us-east-1). Defaults to the environment's configured region.",
)
@click.option(
    "--master-profile",
    default=None,
    help="Named AWS CLI profile for management account access. Mutually exclusive with --master-account-id and --cross-account-role-arn.",
)
@click.option(
    "--last-accessed",
    "last_accessed",
    is_flag=True,
    default=False,
    help=(
        "Enable CloudTrail last-accessed enrichment. "
        "Queries CloudTrail for GetSecretValue events to show when each principal "
        "last accessed the secret. May significantly increase execution time on "
        "accounts with high event volume."
    ),
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress progress messages written to stderr during long-running steps.",
)
@click.option(
    "--versions",
    is_flag=True,
    default=False,
    help="Include secret version metadata (version IDs, staging labels, creation dates) in the report.",
)
@click.option(
    "--allow-partial",
    is_flag=True,
    default=False,
    help=(
        "Continue with a partial report when cross-account access fails. "
        "Only applies when --master-account-id/--cross-account-role-arn or "
        "--master-profile is provided."
    ),
)
@click.option(
    "--ic-region",
    default=None,
    help=(
        "AWS region for Identity Center API calls (e.g. us-east-1). "
        "Optional — the tool auto-detects the IC region when omitted. "
        "Only applies when cross-account flags are provided."
    ),
)
@click.option(
    "--expiry-warning-minutes",
    default=15,
    type=int,
    help="Minutes before credential expiry to warn. 0 to disable. Default: 15.",
)
def main(
    secret: str,
    output_format: str,
    master_account_id: str | None,
    cross_account_role_arn: str | None,
    expand_groups: bool,
    output_file: str | None,
    region: str | None,
    master_profile: str | None,
    last_accessed: bool,
    quiet: bool,
    versions: bool,
    allow_partial: bool,
    ic_region: str | None,
    expiry_warning_minutes: int,
) -> None:
    """Resolve and report who can access an AWS Secrets Manager secret."""
    warnings: list[str] = []

    # --- Validate expiry_warning_minutes ---
    if expiry_warning_minutes < 0:
        raise click.BadParameter("--expiry-warning-minutes must be non-negative.")

    # --- Step 1: Validate inputs ---
    secret = validate_secret_input(secret)
    master_account_id = validate_account_id(master_account_id)
    cross_account_role_arn = validate_role_arn(cross_account_role_arn)
    region = validate_region(region)
    ic_region = validate_region(ic_region)
    master_profile = validate_profile_name(master_profile)

    if master_profile and (master_account_id or cross_account_role_arn):
        raise click.UsageError(
            "--master-profile is mutually exclusive with "
            "--master-account-id and --cross-account-role-arn."
        )

    # --- Progress callback ---
    progress: ProgressCallback = None
    if not quiet:
        def _progress(msg: str) -> None:
            click.echo(msg, err=True)
        progress = _progress

    # --- Step 2: Create production session ---
    prod_session = create_prod_session(region=region)

    # --- Step 2b: Early cross-account validation ---
    cross_session = None
    if master_profile or (master_account_id and cross_account_role_arn):
        if progress:
            progress("Validating cross-account access...")

        if master_profile:
            try:
                cross_session = create_profile_session(master_profile)
                logger.info("Profile session created for %s", master_profile)
            except ProfileSessionError as exc:
                if allow_partial:
                    msg = (
                        f"Unable to create session from profile {master_profile!r}. "
                        f"Displaying permission set name only. "
                        f"Verify profile configuration and credentials."
                    )
                    logger.warning(msg)
                    warnings.append(msg)
                else:
                    click.echo(
                        f"Error: {exc}\n\n"
                        f"Use --allow-partial to continue with a partial report.",
                        err=True,
                    )
                    sys.exit(1)
        elif master_account_id and cross_account_role_arn:
            try:
                cross_session = create_cross_account_session(
                    prod_session, cross_account_role_arn
                )
                logger.info("Cross-account assumption succeeded")
            except CrossAccountError as exc:
                if allow_partial:
                    msg = (
                        f"Unable to assume cross-account role {cross_account_role_arn} "
                        f"in master account {master_account_id}. "
                        f"Displaying permission set name only. "
                        f"Verify trust policy and permissions."
                    )
                    logger.warning(msg)
                    warnings.append(msg)
                else:
                    click.echo(
                        f"Error: {exc}\n\n"
                        f"Use --allow-partial to continue with a partial report.",
                        err=True,
                    )
                    sys.exit(1)

    # --- Step 3: Get operator identity ---
    operator_arn = get_caller_identity(prod_session)
    logger.info("Operator identity: %s", operator_arn)

    # --- Step 4: Resolve secret metadata ---
    secret_meta = resolve_secret(prod_session, secret)
    logger.info("Resolved secret: %s (%s)", secret_meta.name, secret_meta.arn)  # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure

    # --- Step 4b: Fetch version metadata ---
    secret_versions: list[SecretVersionInfo] = []
    if versions:
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
    if expiry_warning_minutes > 0:
        try:
            expiry = get_credential_expiry(prod_session)
            if expiry is not None:
                remaining = (expiry - datetime.now(timezone.utc)).total_seconds() / 60
                if remaining < expiry_warning_minutes:
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
        progress(f"Simulation complete: {len(identity_principals)} of {len(all_principal_arns)} principals have access")

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
            progress(f"Inspecting context keys for {len(remaining_denied)} fully-denied principal(s)...")
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
        principals[i] = classify_principal(prod_session, p)

    # --- Step 7: Identity Center resolution ---
    # cross_session was set in Step 2b (or remains None if no cross-account flags)

    # Extract the target account ID from the secret ARN
    target_account_id = secret_meta.arn.split(":")[4]

    ic_roles = [
        (i, p)
        for i, p in enumerate(principals)
        if p.classification == PrincipalClassification.IDENTITY_CENTER
        and extract_permission_set_name(p.principal_name) is not None
    ]

    if progress and ic_roles and ic_region is None:
        progress("Detecting Identity Center region...")

    if progress and ic_roles:
        progress(f"Resolving {len(ic_roles)} Identity Center role(s)...")

    # Pre-resolve IC instance once before the loop (when cross_session is available)
    ic_instance_found = False
    cached_instance_arn: str | None = None
    cached_identity_store_id: str | None = None
    effective_ic_region: str | None = ic_region

    if cross_session is not None and ic_roles:
        try:
            cached_instance_arn, cached_identity_store_id, detected_region = find_ic_instance(
                cross_session, ic_region=ic_region
            )
            effective_ic_region = ic_region if ic_region is not None else detected_region
            ic_instance_found = True
        except (NoICInstanceError, botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            msg = f"No Identity Center instance found: {exc}"
            warnings.append(msg)
            # Set all IC roles to partial
            for _, p in ic_roles:
                ps_name = extract_permission_set_name(p.principal_name)

                p.ic_resolution = IdentityCenterResolution(
                    permission_set_name=ps_name, partial=True
                )

    if ic_instance_found:
        for role_idx, (i, p) in enumerate(ic_roles):
            if progress:
                progress(f"Resolving Identity Center role {role_idx + 1} of {len(ic_roles)}...")

            ps_name = extract_permission_set_name(p.principal_name)

            try:
                p.ic_resolution = resolve_identity_center(
                    cross_session, ps_name, target_account_id, expand_groups,
                    ic_region=effective_ic_region,
                    instance_arn=cached_instance_arn,
                    identity_store_id=cached_identity_store_id,
                )
            except botocore.exceptions.ClientError as exc:
                if is_expired_token_error(exc):
                    remaining_count = len(ic_roles) - role_idx
                    msg = f"WARNING: Credentials expired during Identity Center resolution. IC data is incomplete for {remaining_count} remaining role(s)."
                    warnings.append(msg)
                    if progress:
                        progress(msg)
                    # Mark remaining roles as partial
                    for remaining_idx in range(role_idx, len(ic_roles)):
                        _, rp = ic_roles[remaining_idx]
                        rp_ps_name = extract_permission_set_name(rp.principal_name)
                        rp.ic_resolution = IdentityCenterResolution(permission_set_name=rp_ps_name, partial=True)
                    break
                raise
    elif cross_session is None:
        # No cross-account session — partial resolution for all IC roles
        for role_idx, (i, p) in enumerate(ic_roles):
            if progress:
                progress(f"Resolving Identity Center role {role_idx + 1} of {len(ic_roles)}...")

            ps_name = extract_permission_set_name(p.principal_name)

            p.ic_resolution = IdentityCenterResolution(
                permission_set_name=ps_name, partial=True
            )

    # --- Step 8: CloudTrail enrichment ---
    if last_accessed:
        principal_arns = [p.principal_arn for p in principals]
        if progress:
            progress("Starting CloudTrail enrichment...")
        try:
            last_accessed_map = get_last_accessed(prod_session, secret_meta.arn, principal_arns, progress=progress)
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

    # --- Step 10: Render and output ---
    rendered = render(report, output_format)

    if output_format == "pdf":
        # PDF is binary — cannot write to stdout
        pdf_path = output_file or "report.pdf"
        try:
            Path(pdf_path).write_bytes(rendered)
            click.echo(f"PDF report written to {pdf_path}")
        except OSError as exc:
            click.echo(f"Error writing to {pdf_path}: {exc}", err=True)
            sys.exit(1)
    elif output_file:
        try:
            Path(output_file).write_text(rendered, encoding="utf-8")
            click.echo(f"Report written to {output_file}")
        except OSError as exc:
            click.echo(f"Error writing to {output_file}: {exc}", err=True)
            sys.exit(1)
    else:
        click.echo(rendered)
