"""Cross-account Identity Center resolution.

Resolves IAM permission set names to Identity Center users and groups by
calling SSO Admin and Identity Store APIs in the master account.  All
functions degrade gracefully: API failures produce partial results with
warnings rather than raising exceptions.

**Security invariant**: this module only calls read-only Identity Center
APIs (``ListInstances``, ``ListPermissionSets``, ``DescribePermissionSet``,
``ListAccountAssignments``, ``DescribeUser``, ``DescribeGroup``,
``ListGroupMemberships``).  It never modifies Identity Center assignments
or user/group records.
"""

from __future__ import annotations

import logging

import botocore.exceptions
from boto3 import Session

from secrets_audit.aws_clients import RETRY_CONFIG
from secrets_audit.models import (
    ICGroupResolution,
    ICUserResolution,
    IdentityCenterResolution,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class NoICInstanceError(Exception):
    """Raised when ``ListInstances`` returns no Identity Center instance."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FALLBACK_REGIONS: list[str] = [
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def find_ic_instance(
    session: Session,
    ic_region: str | None = None,
) -> tuple[str, str, str | None]:
    """Locate the Identity Center instance ARN and identity store ID.

    Calls ``sso-admin:ListInstances`` and returns the first instance
    found.  When *ic_region* is ``None``, tries the session's default
    region first, then iterates :data:`FALLBACK_REGIONS`.

    Parameters
    ----------
    session:
        A boto3 session with credentials for the master account.
    ic_region:
        If provided, only try this region.  If ``None``, try session
        default then iterate ``FALLBACK_REGIONS``.

    Returns
    -------
    tuple[str, str, str | None]
        ``(instance_arn, identity_store_id, detected_region)``
        *detected_region* is ``None`` when the session's default region
        worked, the fallback region string when auto-detection found it
        elsewhere, or *ic_region* when explicitly provided.

    Raises
    ------
    NoICInstanceError
        If no instance found in any tried region.
    """
    # --- Explicit region mode ---
    if ic_region is not None:
        client = session.client(
            "sso-admin", config=RETRY_CONFIG, region_name=ic_region
        )
        logger.debug("ListInstances called in explicit region %s", ic_region)
        response = client.list_instances()
        instances = response.get("Instances", [])
        if not instances:
            logger.warning(
                "ListInstances returned no IC instances in explicit region %s",
                ic_region,
            )
            raise NoICInstanceError(
                f"No Identity Center instance found in region {ic_region}"
            )
        instance = instances[0]
        logger.info("Found IC instance in region %s", ic_region)
        return instance["InstanceArn"], instance["IdentityStoreId"], ic_region

    # --- Auto-detection mode ---
    # 1. Try session default region first
    client = session.client("sso-admin", config=RETRY_CONFIG)
    logger.debug("ListInstances called in session default region")
    response = client.list_instances()
    instances = response.get("Instances", [])
    if instances:
        instance = instances[0]
        logger.info(
            "Found IC instance in session default region: %s (identity store: %s)",
            instance["InstanceArn"],
            instance["IdentityStoreId"],
        )
        return instance["InstanceArn"], instance["IdentityStoreId"], None

    # 2. Iterate fallback regions, skipping session default
    default_region = session.region_name
    for region in FALLBACK_REGIONS:
        if region == default_region:
            continue
        try:
            fallback_client = session.client(
                "sso-admin", config=RETRY_CONFIG, region_name=region
            )
            logger.debug("ListInstances called in fallback region %s", region)
            response = fallback_client.list_instances()
            instances = response.get("Instances", [])
            if instances:
                instance = instances[0]
                logger.info("Found IC instance in fallback region %s", region)
                return (
                    instance["InstanceArn"],
                    instance["IdentityStoreId"],
                    region,
                )
        except (
            botocore.exceptions.ClientError,
            botocore.exceptions.BotoCoreError,
        ) as exc:
            logger.warning(
                "Skipping fallback region %s due to error: %s", region, exc
            )
            continue

    logger.warning("ListInstances returned no IC instances in any region")
    raise NoICInstanceError(
        "No Identity Center instance found in any region"
    )


def find_permission_set_arn(
    session: Session,
    instance_arn: str,
    permission_set_name: str,
    ic_region: str | None = None,
) -> str | None:
    """Paginate ``ListPermissionSets`` and match by name.

    For each permission set ARN returned by ``ListPermissionSets``, calls
    ``DescribePermissionSet`` to compare the name.  Uses manual pagination
    with ``NextToken``.

    Parameters
    ----------
    session:
        A boto3 session with credentials for the master account.
    instance_arn:
        The Identity Center instance ARN.
    permission_set_name:
        The permission set name to search for.

    Returns
    -------
    str | None
        The permission set ARN if found, or ``None``.
    """
    client_kwargs: dict = {"config": RETRY_CONFIG}
    if ic_region:
        client_kwargs["region_name"] = ic_region
    client = session.client("sso-admin", **client_kwargs)
    logger.debug(
        "Searching for permission set '%s' in instance %s",
        permission_set_name,
        instance_arn,
    )

    next_token: str | None = None

    while True:
        kwargs: dict = {"InstanceArn": instance_arn}
        if next_token is not None:
            kwargs["NextToken"] = next_token

        response = client.list_permission_sets(**kwargs)

        for ps_arn in response.get("PermissionSets", []):
            try:
                desc = client.describe_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=ps_arn,
                )
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
                logger.warning(
                    "Failed to describe permission set %s: %s", ps_arn, exc
                )
                continue

            ps_detail = desc.get("PermissionSet", {})
            if ps_detail.get("Name") == permission_set_name:
                logger.info(
                    "Found permission set '%s' → %s",
                    permission_set_name,
                    ps_arn,
                )
                return ps_arn

        next_token = response.get("NextToken")
        if not next_token:
            break

    logger.warning("Permission set '%s' not found", permission_set_name)
    return None


def get_account_assignments(
    session: Session,
    instance_arn: str,
    permission_set_arn: str,
    account_id: str,
    ic_region: str | None = None,
) -> list[dict]:
    """Retrieve account assignments for a permission set and account.

    Calls ``sso-admin:ListAccountAssignments`` with manual pagination.

    Parameters
    ----------
    session:
        A boto3 session with credentials for the master account.
    instance_arn:
        The Identity Center instance ARN.
    permission_set_arn:
        The permission set ARN.
    account_id:
        The target AWS account ID.

    Returns
    -------
    list[dict]
        A list of assignment dicts, each containing ``PrincipalType``,
        ``PrincipalId``, ``AccountId``, and ``PermissionSetArn``.
    """
    client_kwargs: dict = {"config": RETRY_CONFIG}
    if ic_region:
        client_kwargs["region_name"] = ic_region
    client = session.client("sso-admin", **client_kwargs)
    logger.debug(
        "ListAccountAssignments for permission set %s in account %s",
        permission_set_arn,
        account_id,
    )

    assignments: list[dict] = []
    next_token: str | None = None

    while True:
        kwargs: dict = {
            "InstanceArn": instance_arn,
            "AccountId": account_id,
            "PermissionSetArn": permission_set_arn,
        }
        if next_token is not None:
            kwargs["NextToken"] = next_token

        response = client.list_account_assignments(**kwargs)
        assignments.extend(response.get("AccountAssignments", []))

        next_token = response.get("NextToken")
        if not next_token:
            break

    logger.info(
        "Found %d account assignments for permission set in account %s",
        len(assignments),
        account_id,
    )
    return assignments


def resolve_user(
    session: Session,
    identity_store_id: str,
    user_id: str,
    ic_region: str | None = None,
) -> dict:
    """Resolve an Identity Center user by ID.

    Calls ``identitystore:DescribeUser`` to retrieve the display name and
    email.  Handles deleted users gracefully by returning a marker dict.

    Parameters
    ----------
    session:
        A boto3 session with credentials for the master account.
    identity_store_id:
        The Identity Store ID from the IC instance.
    user_id:
        The Identity Center user ID.

    Returns
    -------
    dict
        On success: ``{"display_name": str, "email": str | None, "deleted": False}``
        On deleted user: ``{"user_id": user_id, "deleted": True}``
    """
    client_kwargs: dict = {"config": RETRY_CONFIG}
    if ic_region:
        client_kwargs["region_name"] = ic_region
    client = session.client("identitystore", **client_kwargs)
    logger.debug("DescribeUser for user %s in store %s", user_id, identity_store_id)

    try:
        response = client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id,
        )
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":
            logger.warning("User %s not found (deleted)", user_id)
            return {"user_id": user_id, "deleted": True}
        logger.warning("ClientError %s describing user %s: %s", error_code, user_id, exc)
        return {"user_id": user_id, "deleted": True}
    except botocore.exceptions.BotoCoreError as exc:
        logger.warning("SDK error describing user %s: %s", user_id, exc)
        return {"user_id": user_id, "deleted": True}

    display_name: str = response.get("DisplayName", response.get("UserName", user_id))

    # Extract primary email from the Emails list
    email: str | None = None
    for email_entry in response.get("Emails", []):
        if email_entry.get("Primary", False):
            email = email_entry.get("Value")
            break
    # Fall back to first email if no primary
    if email is None and response.get("Emails"):
        email = response["Emails"][0].get("Value")

    logger.info("Resolved user %s → %s", user_id, display_name)
    return {"display_name": display_name, "email": email, "deleted": False}


def resolve_group(
    session: Session,
    identity_store_id: str,
    group_id: str,
    expand_members: bool = False,
    ic_region: str | None = None,
) -> dict:
    """Resolve an Identity Center group by ID.

    Calls ``identitystore:DescribeGroup`` to get the group name.  When
    ``expand_members`` is ``True``, also calls ``ListGroupMemberships``
    and ``DescribeUser`` for each member.

    Parameters
    ----------
    session:
        A boto3 session with credentials for the master account.
    identity_store_id:
        The Identity Store ID from the IC instance.
    group_id:
        The Identity Center group ID.
    expand_members:
        If ``True``, resolve individual group members.

    Returns
    -------
    dict
        ``{"group_name": str, "members": list[dict], "total_member_count": int}``
    """
    client_kwargs: dict = {"config": RETRY_CONFIG}
    if ic_region:
        client_kwargs["region_name"] = ic_region
    client = session.client("identitystore", **client_kwargs)
    logger.debug("DescribeGroup for group %s in store %s", group_id, identity_store_id)

    try:
        response = client.describe_group(
            IdentityStoreId=identity_store_id,
            GroupId=group_id,
        )
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        logger.warning("ClientError %s describing group %s: %s", error_code, group_id, exc)
        return {"group_name": group_id, "members": [], "total_member_count": 0}
    except botocore.exceptions.BotoCoreError as exc:
        logger.warning("SDK error describing group %s: %s", group_id, exc)
        return {"group_name": group_id, "members": [], "total_member_count": 0}

    group_name: str = response.get("DisplayName", group_id)
    members: list[dict] = []
    total_member_count: int = 0

    if expand_members:
        members, total_member_count = _list_group_members(
            session, identity_store_id, group_id, ic_region=ic_region
        )

    logger.info(
        "Resolved group %s → %s (%d members)",
        group_id,
        group_name,
        total_member_count,
    )
    return {
        "group_name": group_name,
        "members": members,
        "total_member_count": total_member_count,
    }


def resolve_identity_center(
    cross_account_session: Session,
    permission_set_name: str,
    target_account_id: str,
    expand_groups: bool = False,
    ic_region: str | None = None,
    instance_arn: str | None = None,
    identity_store_id: str | None = None,
) -> IdentityCenterResolution:
    """Orchestrate full Identity Center resolution for a permission set.

    Calls the lower-level functions in sequence, catching any exception
    at each step to produce partial results with warnings rather than
    crashing.

    Steps:
    1. Find IC instance → if fails, return partial with warning
       (skipped when *instance_arn* and *identity_store_id* are provided)
    2. Find permission set ARN → if fails or not found, return partial
    3. Get account assignments → if fails, return partial
    4. For each assignment, resolve user or group → if individual
       resolution fails, add warning and continue

    Parameters
    ----------
    cross_account_session:
        A boto3 session with temporary credentials for the master account.
    permission_set_name:
        The permission set name extracted from the IAM role name.
    target_account_id:
        The production account ID where the secret resides.
    expand_groups:
        If ``True``, expand group memberships to individual users.
    ic_region:
        Explicit IC region override.  When ``None``, uses the detected
        region from ``find_ic_instance()``.
    instance_arn:
        Pre-resolved IC instance ARN.  When both *instance_arn* and
        *identity_store_id* are provided, ``find_ic_instance()`` is
        skipped.
    identity_store_id:
        Pre-resolved identity store ID.  When both *instance_arn* and
        *identity_store_id* are provided, ``find_ic_instance()`` is
        skipped.

    Returns
    -------
    IdentityCenterResolution
        Always returns a result — never raises.  ``partial`` is ``True``
        if any step failed.
    """
    result = IdentityCenterResolution(permission_set_name=permission_set_name)

    # Step 1: Find IC instance (skip when pre-resolved values are provided)
    if instance_arn is not None and identity_store_id is not None:
        # Caller already resolved the IC instance — skip find_ic_instance()
        detected_region = None
    else:
        try:
            instance_arn, identity_store_id, detected_region = find_ic_instance(
                cross_account_session, ic_region=ic_region
            )
        except NoICInstanceError:
            msg = (
                "No Identity Center instance found in master account. "
                "Verify account ID configuration."
            )
            logger.warning(msg)
            result.warnings.append(msg)
            result.partial = True
            return result
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            msg = f"Failed to list Identity Center instances: {exc}"
            logger.warning(msg)
            result.warnings.append(msg)
            result.partial = True
            return result

    # Determine effective region for downstream calls
    effective_region = ic_region if ic_region is not None else detected_region

    # Step 2: Find permission set ARN
    try:
        ps_arn = find_permission_set_arn(
            cross_account_session, instance_arn, permission_set_name,
            ic_region=effective_region,
        )
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
        msg = f"Failed to look up permission set '{permission_set_name}': {exc}"
        logger.warning(msg)
        result.warnings.append(msg)
        result.partial = True
        return result

    if ps_arn is None:
        msg = f"Permission set '{permission_set_name}' not found in Identity Center"
        logger.warning(msg)
        result.warnings.append(msg)
        result.partial = True
        return result

    # Step 3: Get account assignments
    try:
        assignments = get_account_assignments(
            cross_account_session, instance_arn, ps_arn, target_account_id,
            ic_region=effective_region,
        )
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
        msg = (
            f"Failed to list account assignments for permission set "
            f"'{permission_set_name}': {exc}"
        )
        logger.warning(msg)
        result.warnings.append(msg)
        result.partial = True
        return result

    # Step 4: Resolve each assignment
    for assignment in assignments:
        principal_type = assignment.get("PrincipalType", "")
        principal_id = assignment.get("PrincipalId", "")

        if principal_type == "USER":
            _resolve_user_assignment(
                cross_account_session,
                identity_store_id,
                principal_id,
                result,
                ic_region=effective_region,
            )
        elif principal_type == "GROUP":
            _resolve_group_assignment(
                cross_account_session,
                identity_store_id,
                principal_id,
                expand_groups,
                result,
                ic_region=effective_region,
            )
        else:
            logger.warning(
                "Unknown assignment principal type '%s' for ID %s",
                principal_type,
                principal_id,
            )

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _list_group_members(
    session: Session,
    identity_store_id: str,
    group_id: str,
    ic_region: str | None = None,
) -> tuple[list[dict], int]:
    """List and resolve all members of an Identity Center group.

    Calls ``identitystore:ListGroupMemberships`` with manual pagination,
    then ``resolve_user`` for each member.

    Returns
    -------
    tuple[list[dict], int]
        ``(resolved_members, total_count)``
    """
    client_kwargs: dict = {"config": RETRY_CONFIG}
    if ic_region:
        client_kwargs["region_name"] = ic_region
    client = session.client("identitystore", **client_kwargs)
    member_ids: list[str] = []
    next_token: str | None = None

    try:
        while True:
            kwargs: dict = {
                "IdentityStoreId": identity_store_id,
                "GroupId": group_id,
            }
            if next_token is not None:
                kwargs["NextToken"] = next_token

            response = client.list_group_memberships(**kwargs)

            for membership in response.get("GroupMemberships", []):
                member_id_obj = membership.get("MemberId", {})
                user_id = member_id_obj.get("UserId")
                if user_id:
                    member_ids.append(user_id)

            next_token = response.get("NextToken")
            if not next_token:
                break
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
        logger.warning(
            "Failed to list group memberships for group %s: %s", group_id, exc
        )
        return [], 0

    total_count = len(member_ids)
    resolved: list[dict] = []

    for uid in member_ids:
        user_info = resolve_user(session, identity_store_id, uid, ic_region=ic_region)
        resolved.append(user_info)

    return resolved, total_count


def _resolve_user_assignment(
    session: Session,
    identity_store_id: str,
    user_id: str,
    result: IdentityCenterResolution,
    ic_region: str | None = None,
) -> None:
    """Resolve a single user assignment and append to the result."""
    try:
        user_info = resolve_user(session, identity_store_id, user_id, ic_region=ic_region)
    except Exception as exc:
        msg = f"Failed to resolve user {user_id}: {exc}"
        logger.warning(msg)
        result.warnings.append(msg)
        return

    if user_info.get("deleted"):
        display = f"User ID: {user_id} (deleted)"
        logger.warning("Deleted user encountered: %s", user_id)
        result.users.append(
            ICUserResolution(
                user_id=user_id,
                display_name=display,
                deleted=True,
            )
        )
    else:
        result.users.append(
            ICUserResolution(
                user_id=user_id,
                display_name=user_info.get("display_name"),
                email=user_info.get("email"),
                deleted=False,
            )
        )


def _resolve_group_assignment(
    session: Session,
    identity_store_id: str,
    group_id: str,
    expand_members: bool,
    result: IdentityCenterResolution,
    ic_region: str | None = None,
) -> None:
    """Resolve a single group assignment and append to the result."""
    try:
        group_info = resolve_group(
            session, identity_store_id, group_id, expand_members=expand_members,
            ic_region=ic_region,
        )
    except Exception as exc:
        msg = f"Failed to resolve group {group_id}: {exc}"
        logger.warning(msg)
        result.warnings.append(msg)
        return

    group_name = group_info.get("group_name", group_id)
    raw_members = group_info.get("members", [])
    total_count = group_info.get("total_member_count", 0)

    # Convert raw member dicts to ICUserResolution objects
    members: list[ICUserResolution] = []
    for m in raw_members:
        if m.get("deleted"):
            uid = m.get("user_id", "unknown")
            members.append(
                ICUserResolution(
                    user_id=uid,
                    display_name=f"User ID: {uid} (deleted)",
                    deleted=True,
                    via_group=group_name,
                )
            )
        else:
            members.append(
                ICUserResolution(
                    user_id=m.get("user_id", "unknown"),
                    display_name=m.get("display_name"),
                    email=m.get("email"),
                    deleted=False,
                    via_group=group_name,
                )
            )

    result.groups.append(
        ICGroupResolution(
            group_id=group_id,
            group_name=group_name,
            members=members,
            total_member_count=total_count,
        )
    )
