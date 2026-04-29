"""Secret metadata resolution and principal enumeration.

Resolves secret metadata via ``DescribeSecret``, enumerates IAM principals
with access via the IAM Policy Simulator and resource-based policy parsing,
and derives access levels from allowed actions.

**Security invariant**: this module NEVER calls ``GetSecretValue``.  It only
reads metadata, policies, and simulation results.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import botocore.exceptions
from boto3 import Session

from secrets_audit.aws_clients import RETRY_CONFIG, is_expired_token_error
from secrets_audit.models import (
    AccessLevel,
    PrincipalAccess,
    PrincipalType,
    SecretMetadata,
    SecretVersionInfo,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Action classification sets
# ---------------------------------------------------------------------------

_READ_ACTIONS: frozenset[str] = frozenset({
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret",
})

_WRITE_ACTIONS: frozenset[str] = frozenset({
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
})

_ADMIN_ACTIONS: frozenset[str] = frozenset({
    "secretsmanager:DeleteSecret",
    "secretsmanager:CreateSecret",
    "secretsmanager:*",
})

DEFAULT_ACTIONS: list[str] = [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:DeleteSecret",
    "secretsmanager:CreateSecret",
    "secretsmanager:DescribeSecret",
]

# Batching: ~5 requests per second → sleep 0.2s between individual calls
_BATCH_SLEEP: float = 0.2


# ---------------------------------------------------------------------------
# SimulationResult
# ---------------------------------------------------------------------------


@dataclass
class SimulationResult:
    """Result of simulate_principal_access(), including truncation metadata."""
    principals: list[PrincipalAccess]
    truncated: bool = False
    evaluated_count: int = 0
    total_count: int = 0
    fully_denied_arns: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Secret metadata
# ---------------------------------------------------------------------------


def resolve_secret(session: Session, secret_identifier: str) -> SecretMetadata:
    """Call ``DescribeSecret`` to retrieve secret name, ARN, and metadata.

    NOTE: This function NEVER calls ``GetSecretValue``.

    Parameters
    ----------
    session:
        A boto3 session for the production account.
    secret_identifier:
        A secret name or full ARN.

    Returns
    -------
    SecretMetadata
        Populated from the ``DescribeSecret`` response.

    Raises
    ------
    SystemExit
        If the secret is not found or access is denied.
    """
    client = session.client("secretsmanager", config=RETRY_CONFIG)
    # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
    logger.debug("DescribeSecret called with SecretId=%s", secret_identifier)

    try:
        response = client.describe_secret(SecretId=secret_identifier)
    except client.exceptions.ResourceNotFoundException:
        # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
        logger.error("Secret not found: %s", secret_identifier)
        print(f"Error: Secret not found: {secret_identifier}", file=sys.stderr)
        sys.exit(1)
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "AccessDeniedException":
            # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
            logger.error("Access denied on DescribeSecret for %s", secret_identifier)
            print(
                f"Error: Access denied on DescribeSecret for {secret_identifier}",
                file=sys.stderr,
            )
            sys.exit(1)
        # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
        logger.error("ClientError %s on DescribeSecret: %s", error_code, exc)
        raise
    except botocore.exceptions.BotoCoreError as exc:
        # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
        logger.error("SDK error on DescribeSecret: %s", exc)
        raise

    logger.info("Resolved secret: %s", response.get("Name"))  # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure

    return SecretMetadata(
        name=response["Name"],
        arn=response["ARN"],
        description=response.get("Description"),
        kms_key_id=response.get("KmsKeyId"),
        rotation_enabled=response.get("RotationEnabled", False),
        tags={t["Key"]: t["Value"] for t in response.get("Tags", [])},
    )


def list_secret_versions(
    session: Session,
    secret_arn: str,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[SecretVersionInfo], list[str]]:
    """Fetch all version metadata for a secret via ListSecretVersionIds.

    Returns a tuple of (versions, warnings).  Paginates using NextToken.
    On ``AccessDeniedException`` or ``ResourceNotFoundException``, returns
    ``([], [warning_msg])``.

    NOTE: This function NEVER calls ``GetSecretValue``.

    Parameters
    ----------
    session:
        A boto3 session for the production account.
    secret_arn:
        The target secret ARN.
    progress:
        Optional callback for progress messages.

    Returns
    -------
    tuple[list[SecretVersionInfo], list[str]]
        A list of version metadata objects and a list of warning strings.
    """
    client = session.client("secretsmanager", config=RETRY_CONFIG)
    versions: list[SecretVersionInfo] = []

    # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
    logger.debug("ListSecretVersionIds called with SecretId=%s", secret_arn)

    try:
        next_token: str | None = None
        while True:
            kwargs: dict[str, str] = {"SecretId": secret_arn}
            if next_token is not None:
                kwargs["NextToken"] = next_token

            # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
            logger.debug("ListSecretVersionIds page request for %s", secret_arn)
            response = client.list_secret_version_ids(**kwargs)

            for entry in response.get("Versions", []):
                versions.append(
                    SecretVersionInfo(
                        version_id=entry["VersionId"],
                        staging_labels=entry.get("VersionStages", []),
                        created_date=entry.get("CreatedDate"),
                    )
                )

            if progress:
                progress(f"Fetching version metadata... {len(versions)} versions retrieved")

            next_token = response.get("NextToken")
            if not next_token:
                break

    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "AccessDeniedException":
            # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
            logger.warning(
                "Access denied on ListSecretVersionIds for %s", secret_arn
            )
            return ([], ["Version metadata unavailable: access denied on ListSecretVersionIds"])
        if error_code == "ResourceNotFoundException":
            # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
            logger.warning(
                "Secret not found on ListSecretVersionIds for %s", secret_arn
            )
            return ([], ["Version metadata unavailable: secret not found"])
        # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
        logger.error(
            "ClientError %s on ListSecretVersionIds: %s", error_code, exc
        )
        raise
    except botocore.exceptions.BotoCoreError as exc:
        # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
        logger.error("SDK error on ListSecretVersionIds: %s", exc)
        raise

    # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
    logger.info(
        "Retrieved %d version(s) for %s", len(versions), secret_arn
    )
    return (versions, [])


# ---------------------------------------------------------------------------
# IAM principal listing (paginators)
# ---------------------------------------------------------------------------


def list_iam_roles(session: Session) -> list[str]:
    """List all IAM role ARNs in the account.

    Uses a paginator to handle accounts with many roles.

    Parameters
    ----------
    session:
        A boto3 session for the production account.

    Returns
    -------
    list[str]
        A list of IAM role ARNs.
    """
    client = session.client("iam", config=RETRY_CONFIG)
    logger.debug("Listing IAM roles via paginator")

    arns: list[str] = []
    try:
        paginator = client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                arns.append(role["Arn"])
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        logger.error("ClientError %s listing IAM roles: %s", error_code, exc)
        raise
    except botocore.exceptions.BotoCoreError as exc:
        logger.error("SDK error listing IAM roles: %s", exc)
        raise

    logger.info("Found %d IAM roles", len(arns))
    return arns


def list_iam_users(session: Session) -> list[str]:
    """List all IAM user ARNs in the account.

    Uses a paginator to handle accounts with many users.

    Parameters
    ----------
    session:
        A boto3 session for the production account.

    Returns
    -------
    list[str]
        A list of IAM user ARNs.
    """
    client = session.client("iam", config=RETRY_CONFIG)
    logger.debug("Listing IAM users via paginator")

    arns: list[str] = []
    try:
        paginator = client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                arns.append(user["Arn"])
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        logger.error("ClientError %s listing IAM users: %s", error_code, exc)
        raise
    except botocore.exceptions.BotoCoreError as exc:
        logger.error("SDK error listing IAM users: %s", exc)
        raise

    logger.info("Found %d IAM users", len(arns))
    return arns


# ---------------------------------------------------------------------------
# IAM Policy Simulator
# ---------------------------------------------------------------------------


def _principal_type_from_arn(arn: str) -> PrincipalType:
    """Infer the principal type from an IAM ARN."""
    if ":user/" in arn:
        return PrincipalType.IAM_USER
    if ":role/" in arn:
        return PrincipalType.IAM_ROLE
    if ":group/" in arn:
        return PrincipalType.IAM_GROUP
    # Default to role for unknown patterns
    return PrincipalType.IAM_ROLE


def _principal_name_from_arn(arn: str) -> str:
    """Extract the friendly name from an IAM ARN (last segment after '/')."""
    return arn.rsplit("/", 1)[-1] if "/" in arn else arn


def simulate_principal_access(
    session: Session,
    principal_arns: list[str],
    secret_arn: str,
    actions: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
    resource_tags: dict[str, str] | None = None,
) -> SimulationResult:
    """Evaluate which principals have Allow for secretsmanager actions on a secret.

    Calls ``SimulatePrincipalPolicy`` one principal at a time with batching
    (~5 req/sec) and relies on the adaptive retry config for throttling.

    Parameters
    ----------
    session:
        A boto3 session for the production account.
    principal_arns:
        IAM principal ARNs to evaluate.
    secret_arn:
        The target secret ARN used as the resource in simulation.
    actions:
        Secretsmanager actions to simulate.  Defaults to
        :data:`DEFAULT_ACTIONS`.

    Returns
    -------
    SimulationResult
        Contains the list of principals with access, plus truncation metadata.
    """
    if actions is None:
        actions = DEFAULT_ACTIONS

    context_entries = []
    for k, v in (resource_tags or {}).items():
        # Pass both the global and service-specific tag condition keys.
        # Policies may use either aws:ResourceTag/<key> or
        # secretsmanager:ResourceTag/<key> — the simulator needs both.
        context_entries.append(
            {"ContextKeyName": f"aws:ResourceTag/{k}",
             "ContextKeyValues": [v], "ContextKeyType": "string"}
        )
        context_entries.append(
            {"ContextKeyName": f"secretsmanager:ResourceTag/{k}",
             "ContextKeyValues": [v], "ContextKeyType": "string"}
        )

    client = session.client("iam", config=RETRY_CONFIG)
    results: list[PrincipalAccess] = []
    fully_denied: list[str] = []

    logger.info(
        "Simulating access for %d principals against %s",
        len(principal_arns),
        secret_arn,
    )

    total = len(principal_arns)
    interval = 1 if total < 20 else 10

    for idx, principal_arn in enumerate(principal_arns):
        if progress is not None and idx > 0 and idx % interval == 0:
            progress(f"Simulating principals... ({idx}/{total})")

        logger.debug(
            "SimulatePrincipalPolicy for %s (%d/%d)",
            principal_arn,
            idx + 1,
            len(principal_arns),
        )

        try:
            response = client.simulate_principal_policy(
                PolicySourceArn=principal_arn,
                ActionNames=actions,
                ResourceArns=[secret_arn],
                ContextEntries=context_entries,
            )
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code == "AccessDeniedException":
                logger.error(
                    "Access denied simulating policy for %s — skipping",
                    principal_arn,
                )
                continue
            if error_code == "NoSuchEntity":
                logger.warning(
                    "Principal %s no longer exists — skipping",
                    principal_arn,
                )
                continue
            if is_expired_token_error(exc):
                logger.warning(
                    "Credentials expired during simulation at principal %d of %d",
                    idx + 1, total,
                )
                return SimulationResult(
                    principals=results, truncated=True,
                    evaluated_count=idx, total_count=total,
                    fully_denied_arns=fully_denied,
                )
            # Let adaptive retry handle throttling; re-raise others
            logger.error(
                "ClientError %s simulating policy for %s: %s",
                error_code,
                principal_arn,
                exc,
            )
            raise
        except botocore.exceptions.BotoCoreError as exc:
            logger.error(
                "SDK error simulating policy for %s: %s", principal_arn, exc
            )
            raise

        # Collect allowed actions from evaluation results
        allowed: list[str] = []
        for result in response.get("EvaluationResults", []):
            action = result["EvalActionName"]
            if result.get("EvalDecision") == "allowed":
                allowed.append(action)
                continue
            # Check resource-specific results for scoped Resource policies
            for rsr in result.get("ResourceSpecificResults", []):
                if rsr.get("EvalResourceDecision") == "allowed":
                    allowed.append(action)
                    break

        # Track fully-denied principals: all actions must have implicitDeny
        # with empty MatchedStatements and no allowed ResourceSpecificResults.
        # Do NOT classify as fully denied if any action has explicitDeny,
        # non-empty MatchedStatements, or any allowed decision.
        if not allowed:
            is_fully_denied = True
            for result in response.get("EvaluationResults", []):
                decision = result.get("EvalDecision")
                matched = result.get("MatchedStatements", [])
                if decision != "implicitDeny" or matched:
                    is_fully_denied = False
                    break
                # Check ResourceSpecificResults for any allowed decision
                for rsr in result.get("ResourceSpecificResults", []):
                    if rsr.get("EvalResourceDecision") == "allowed":
                        is_fully_denied = False
                        break
                if not is_fully_denied:
                    break
            if is_fully_denied and response.get("EvaluationResults"):
                fully_denied.append(principal_arn)

        if allowed:
            access_level = derive_access_level(allowed)
            results.append(
                PrincipalAccess(
                    principal_type=_principal_type_from_arn(principal_arn),
                    principal_arn=principal_arn,
                    principal_name=_principal_name_from_arn(principal_arn),
                    access_level=access_level,
                    allowed_actions=allowed,
                    policy_source="identity_policy",
                )
            )

        # Rate-limit: sleep between calls to stay under ~5 req/sec
        if idx < len(principal_arns) - 1:
            time.sleep(_BATCH_SLEEP)

    logger.info(
        "Simulation complete: %d of %d principals have access",
        len(results),
        len(principal_arns),
    )
    return SimulationResult(
        principals=results, truncated=False,
        evaluated_count=total, total_count=total,
        fully_denied_arns=fully_denied,
    )


# ---------------------------------------------------------------------------
# Context key inspection
# ---------------------------------------------------------------------------

_RESOURCE_TAG_PREFIX = "secretsmanager:ResourceTag/"


def inspect_context_keys(
    session: Session,
    principal_arns: list[str],
    progress: Callable[[str], None] | None = None,
) -> tuple[list[str], list[str]]:
    """Check fully-denied principals for secretsmanager:ResourceTag/ context keys.

    Calls ``GetContextKeysForPrincipalPolicy`` for each principal ARN and
    checks whether any returned key starts with ``secretsmanager:ResourceTag/``.
    If so, a warning is emitted because the IAM Policy Simulator cannot
    evaluate those condition keys.

    **Security invariant**: this function NEVER calls ``GetSecretValue``.

    Parameters
    ----------
    session:
        A boto3 session for the production account.
    principal_arns:
        IAM principal ARNs to inspect (should be fully-denied principals).
    progress:
        Optional callback for progress messages.

    Returns
    -------
    tuple[list[str], list[str]]
        ``(flagged_warnings, inspection_warnings)`` where *flagged_warnings*
        are limitation warnings for principals whose policies reference
        ``secretsmanager:ResourceTag/`` keys, and *inspection_warnings* are
        operational warnings (e.g. credential expiry).
    """
    client = session.client("iam", config=RETRY_CONFIG)
    flagged_warnings: list[str] = []
    inspection_warnings: list[str] = []

    total = len(principal_arns)
    logger.info("Inspecting context keys for %d fully-denied principal(s)", total)

    for idx, principal_arn in enumerate(principal_arns):
        if progress is not None and idx > 0:
            progress(f"Inspecting context keys... ({idx}/{total})")

        logger.debug(
            "GetContextKeysForPrincipalPolicy for %s (%d/%d)",
            principal_arn, idx + 1, total,
        )

        try:
            response = client.get_context_keys_for_principal_policy(
                PolicySourceArn=principal_arn,
            )
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code in ("AccessDeniedException", "AccessDenied"):
                logger.warning(
                    "Access denied on GetContextKeysForPrincipalPolicy for %s — skipping",
                    principal_arn,
                )
                continue
            if error_code == "NoSuchEntity":
                logger.debug(
                    "Principal %s no longer exists — skipping context key inspection",
                    principal_arn,
                )
                continue
            if is_expired_token_error(exc):
                logger.warning(
                    "Credentials expired during context key inspection at principal %d of %d",
                    idx + 1, total,
                )
                inspection_warnings.append(
                    "Context key inspection incomplete: credentials expired before all "
                    "fully-denied principals could be inspected."
                )
                break
            # Let adaptive retry handle throttling; re-raise others
            logger.error(
                "ClientError %s on GetContextKeysForPrincipalPolicy for %s: %s",
                error_code, principal_arn, exc,
            )
            raise
        except botocore.exceptions.BotoCoreError as exc:
            logger.error(
                "SDK error on GetContextKeysForPrincipalPolicy for %s: %s",
                principal_arn, exc,
            )
            raise

        context_keys: list[str] = response.get("ContextKeyNames", [])
        has_resource_tag_key = any(
            k.startswith(_RESOURCE_TAG_PREFIX) for k in context_keys
        )

        if has_resource_tag_key:
            name = _principal_name_from_arn(principal_arn)
            flagged_warnings.append(
                f"Principal {name} has policies using secretsmanager:ResourceTag "
                f"conditions which the IAM Policy Simulator cannot evaluate. "
                f"This principal may have access that is not reflected in this report."
            )

        # Rate-limit: sleep between calls to stay under ~5 req/sec
        if idx < total - 1:
            time.sleep(_BATCH_SLEEP)

    logger.info(
        "Context key inspection complete: %d warning(s) flagged",
        len(flagged_warnings),
    )
    return (flagged_warnings, inspection_warnings)


# ---------------------------------------------------------------------------
# Resource-based policy parsing
# ---------------------------------------------------------------------------


def get_resource_policy_principals(
    session: Session, secret_arn: str
) -> list[PrincipalAccess]:
    """Parse the resource-based policy on a secret to extract Allow principals.

    Calls ``GetResourcePolicy`` (read-only — never modifies the policy) and
    inspects each ``Statement`` with ``"Effect": "Allow"`` to collect
    principal ARNs.  Deny statements are intentionally ignored.

    Parameters
    ----------
    session:
        A boto3 session for the production account.
    secret_arn:
        The target secret ARN.

    Returns
    -------
    list[PrincipalAccess]
        One entry per unique principal found in Allow statements.
    """
    client = session.client("secretsmanager", config=RETRY_CONFIG)
    logger.debug("GetResourcePolicy for %s", secret_arn)

    try:
        response = client.get_resource_policy(SecretId=secret_arn)
    except client.exceptions.ResourceNotFoundException:
        logger.warning("Secret %s not found when fetching resource policy", secret_arn)
        return []
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "AccessDeniedException":
            logger.error("Access denied fetching resource policy for %s", secret_arn)
            return []
        logger.error(
            "ClientError %s fetching resource policy: %s", error_code, exc
        )
        raise
    except botocore.exceptions.BotoCoreError as exc:
        logger.error("SDK error fetching resource policy: %s", exc)
        raise

    policy_json = response.get("ResourcePolicy")
    if not policy_json:
        logger.info("No resource-based policy on %s", secret_arn)
        return []

    try:
        policy: dict[str, Any] = json.loads(policy_json)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse resource policy JSON for %s", secret_arn)
        return []

    # Extract principals from Allow statements only
    seen_arns: set[str] = set()
    results: list[PrincipalAccess] = []

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        # Collect actions from this statement to derive access level
        raw_actions = statement.get("Action", [])
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]

        # Normalise action names to include the service prefix if missing
        actions: list[str] = []
        for action in raw_actions:
            if ":" not in action:
                action = f"secretsmanager:{action}"
            actions.append(action)

        # Extract principals — can be a string or a dict with AWS/Service keys
        principal_field = statement.get("Principal", {})
        principal_arns: list[str] = _extract_principal_arns(principal_field)

        for arn in principal_arns:
            if arn in seen_arns:
                continue
            seen_arns.add(arn)

            access_level = derive_access_level(actions) if actions else AccessLevel.READ
            results.append(
                PrincipalAccess(
                    principal_type=_principal_type_from_arn(arn),
                    principal_arn=arn,
                    principal_name=_principal_name_from_arn(arn),
                    access_level=access_level,
                    allowed_actions=actions,
                    policy_source="resource_policy",
                )
            )

    logger.info(
        "Resource policy on %s grants access to %d principals",
        secret_arn,
        len(results),
    )
    return results


def _extract_principal_arns(principal_field: Any) -> list[str]:
    """Extract ARN strings from a policy Principal field.

    The ``Principal`` field in an IAM policy statement can be:
    - ``"*"`` (wildcard — skipped, not a real ARN)
    - A string ARN
    - A dict like ``{"AWS": "arn:..."}`` or ``{"AWS": ["arn:...", ...]}``
    """
    arns: list[str] = []

    if isinstance(principal_field, str):
        if principal_field != "*":
            arns.append(principal_field)
        return arns

    if isinstance(principal_field, dict):
        for key in ("AWS", "Service", "Federated"):
            value = principal_field.get(key)
            if value is None:
                continue
            if isinstance(value, str):
                if value != "*":
                    arns.append(value)
            elif isinstance(value, list):
                arns.extend(v for v in value if isinstance(v, str) and v != "*")

    return arns


# ---------------------------------------------------------------------------
# Access level derivation
# ---------------------------------------------------------------------------


def derive_access_level(allowed_actions: list[str]) -> AccessLevel:
    """Map allowed secretsmanager actions to an :class:`AccessLevel`.

    Precedence rules (from the design document):

    1. **Admin** — if any action in ``allowed_actions`` is ``DeleteSecret``,
       ``CreateSecret``, or ``secretsmanager:*``, the level is ``Admin``
       regardless of other actions.
    2. **Read/Write** — if both read and write actions are present.
    3. **Write** — if only write actions are present (no read actions).
    4. **Read** — if only ``GetSecretValue`` and/or ``DescribeSecret``.

    Parameters
    ----------
    allowed_actions:
        A list of secretsmanager action strings (e.g.
        ``"secretsmanager:GetSecretValue"``).

    Returns
    -------
    AccessLevel
        The derived access level.
    """
    if not allowed_actions:
        return AccessLevel.READ

    action_set = frozenset(allowed_actions)

    # Admin takes precedence over everything
    if action_set & _ADMIN_ACTIONS:
        return AccessLevel.ADMIN

    has_read = bool(action_set & _READ_ACTIONS)
    has_write = bool(action_set & _WRITE_ACTIONS)

    if has_read and has_write:
        return AccessLevel.READ_WRITE
    if has_write:
        return AccessLevel.WRITE
    return AccessLevel.READ
