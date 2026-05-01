"""Principal classification — Identity Center, EKS, or plain IAM.

Inspects IAM role trust policies to classify principals as Identity
Center-managed roles, EKS service account roles, or plain IAM entities.
Classification is mutually exclusive: IC takes priority over EKS, which
takes priority over PLAIN_IAM.

**Security invariant**: this module only calls ``iam:GetRole`` (a read-only
API).  It never modifies IAM policies or role configurations.
"""

from __future__ import annotations

import logging
import re

import botocore.exceptions
from boto3 import Session

from secrets_audit.aws_clients import RETRY_CONFIG
from secrets_audit.models import (
    AccountSnapshot,
    PrincipalAccess,
    PrincipalClassification,
    PrincipalType,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Permission set name pattern
# ---------------------------------------------------------------------------
# Role names created by Identity Center follow:
#   AWSReservedSSO_<PermissionSetName>_<12-char-hex-hash>
_PERMISSION_SET_RE = re.compile(r"^AWSReservedSSO_(.+)_[a-f0-9]{12,}$")

# OIDC provider ARN pattern used by EKS
_OIDC_PROVIDER_RE = re.compile(r"^arn:aws:iam::\d{12}:oidc-provider/.+")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_principal(
    session: Session,
    principal: PrincipalAccess,
    account_snapshot: AccountSnapshot | None = None,
) -> PrincipalAccess:
    """Inspect the principal's trust policy and classify it.

    Only IAM roles are inspected — users and groups default to
    ``PLAIN_IAM``.  For roles, the function calls ``iam:GetRole`` to
    retrieve the trust policy and checks (in order):

    1. **IDENTITY_CENTER** — trust policy contains ``sso.amazonaws.com``
       as a principal, or the role path matches
       ``/aws-reserved/sso.amazonaws.com/``.
    2. **EKS_SERVICE_ACCOUNT** — trust policy contains an OIDC provider
       principal.
    3. **PLAIN_IAM** — default.

    When *account_snapshot* is provided, the trust policy and path are
    read from the snapshot instead of calling ``GetRole``.

    On ``GetRole`` failure the principal is left as ``PLAIN_IAM`` with a
    warning logged.

    **Security invariant**: this module only calls ``iam:GetRole`` (a read-only
    API).  It never modifies IAM policies or role configurations.

    Parameters
    ----------
    session:
        A boto3 session for the production account.
    principal:
        The :class:`PrincipalAccess` to classify.  Mutated in place.
    account_snapshot:
        Optional pre-loaded GAAD snapshot.  When provided, trust policy
        and path are read from the snapshot instead of calling ``GetRole``.

    Returns
    -------
    PrincipalAccess
        The same object with ``classification``, ``ic_resolution``, and
        ``eks_detail`` fields updated as appropriate.
    """
    # Only roles get classified; users/groups stay PLAIN_IAM
    if principal.principal_type != PrincipalType.IAM_ROLE:
        principal.classification = PrincipalClassification.PLAIN_IAM
        return principal

    if account_snapshot is not None:
        # Read trust policy and path from the pre-loaded GAAD snapshot
        snap_entry = account_snapshot.get(principal.principal_arn)
        if snap_entry is None:
            # Role not in snapshot — default to PLAIN_IAM
            principal.classification = PrincipalClassification.PLAIN_IAM
            return principal
        trust_policy = snap_entry.get("trust_policy", {})
        role_path = snap_entry.get("path", "/")
    else:
        # Existing behavior: fetch the role's trust policy via GetRole
        trust_policy, role_path = _get_role_trust_policy(
            session, principal.principal_name
        )

        if trust_policy is None:
            # GetRole failed — default to PLAIN_IAM (warning already logged)
            principal.classification = PrincipalClassification.PLAIN_IAM
            return principal

    role_name = principal.principal_name

    # Check in priority order: IC → EKS → PLAIN_IAM
    if is_identity_center_role(role_name, trust_policy, role_path):
        principal.classification = PrincipalClassification.IDENTITY_CENTER
        perm_set_name = extract_permission_set_name(role_name)
        if perm_set_name:
            logger.info(
                "Role %s classified as IDENTITY_CENTER (permission set: %s)",
                role_name,
                perm_set_name,
            )
        else:
            logger.info(
                "Role %s classified as IDENTITY_CENTER (no permission set name extracted)",
                role_name,
            )
        return principal

    is_eks, eks_detail = is_eks_service_account(trust_policy)
    if is_eks:
        principal.classification = PrincipalClassification.EKS_SERVICE_ACCOUNT
        principal.eks_detail = eks_detail
        logger.info(
            "Role %s classified as EKS_SERVICE_ACCOUNT: %s",
            role_name,
            eks_detail,
        )
        return principal

    # Default
    principal.classification = PrincipalClassification.PLAIN_IAM
    logger.debug("Role %s classified as PLAIN_IAM", role_name)
    return principal


def is_identity_center_role(
    role_name: str,
    trust_policy: dict,
    role_path: str | None = None,
) -> bool:
    """Check whether a role is managed by Identity Center.

    Returns ``True`` if:
    - The trust policy contains ``sso.amazonaws.com`` as a principal
      (in the ``Service`` field), **or**
    - The role path matches ``/aws-reserved/sso.amazonaws.com/``.

    Parameters
    ----------
    role_name:
        The IAM role name.
    trust_policy:
        The ``AssumeRolePolicyDocument`` dict from ``GetRole``.
    role_path:
        The role's ``Path`` from ``GetRole`` (e.g.
        ``/aws-reserved/sso.amazonaws.com/us-east-1/``).
    """
    # Check role path
    if role_path and "/aws-reserved/sso.amazonaws.com/" in role_path:
        return True

    # Check trust policy for sso.amazonaws.com as a service principal
    for statement in trust_policy.get("Statement", []):
        principal_field = statement.get("Principal", {})
        if _has_sso_principal(principal_field):
            return True

    return False


def is_eks_service_account(
    trust_policy: dict,
) -> tuple[bool, str | None]:
    """Check whether a trust policy references an EKS OIDC provider.

    Scans the ``Federated`` principal field for ARNs matching the
    pattern ``arn:aws:iam::*:oidc-provider/*``.

    Parameters
    ----------
    trust_policy:
        The ``AssumeRolePolicyDocument`` dict from ``GetRole``.

    Returns
    -------
    tuple[bool, str | None]
        ``(True, detail_string)`` if an OIDC provider is found, or
        ``(False, None)`` otherwise.  The detail string is of the form
        ``"Assumed via EKS OIDC provider: <arn>"``.
    """
    for statement in trust_policy.get("Statement", []):
        principal_field = statement.get("Principal", {})
        oidc_arn = _find_oidc_provider(principal_field)
        if oidc_arn is not None:
            detail = f"Assumed via EKS OIDC provider: {oidc_arn}"
            return True, detail

    return False, None


def extract_permission_set_name(role_name: str) -> str | None:
    """Extract the permission set name from an IC-managed role name.

    Role names follow the pattern
    ``AWSReservedSSO_<PermissionSetName>_<12-char-hex-hash>``.

    Parameters
    ----------
    role_name:
        The IAM role name (not the full ARN).

    Returns
    -------
    str | None
        The permission set name, or ``None`` if the pattern does not
        match.

    Examples
    --------
    >>> extract_permission_set_name("AWSReservedSSO_AdministratorAccess_1234abcd5678")
    'AdministratorAccess'
    >>> extract_permission_set_name("my-regular-role") is None
    True
    """
    match = _PERMISSION_SET_RE.match(role_name)
    if match:
        return match.group(1)
    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_role_trust_policy(
    session: Session, role_name: str
) -> tuple[dict | None, str | None]:
    """Call ``iam:GetRole`` and return the trust policy and path.

    Returns ``(None, None)`` on any failure, with a WARNING logged.
    """
    client = session.client("iam", config=RETRY_CONFIG)
    logger.debug("GetRole called for %s", role_name)

    try:
        response = client.get_role(RoleName=role_name)
    except client.exceptions.NoSuchEntityException:
        logger.warning("Role %s not found (NoSuchEntity)", role_name)
        return None, None
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "AccessDenied":
            logger.warning(
                "Access denied on GetRole for %s — defaulting to PLAIN_IAM",
                role_name,
            )
        else:
            logger.warning(
                "ClientError %s on GetRole for %s: %s",
                error_code,
                role_name,
                exc,
            )
        return None, None
    except botocore.exceptions.BotoCoreError as exc:
        logger.warning("SDK error on GetRole for %s: %s", role_name, exc)
        return None, None

    role = response.get("Role", {})
    trust_policy: dict = role.get("AssumeRolePolicyDocument", {})
    role_path: str = role.get("Path", "/")
    return trust_policy, role_path


def _has_sso_principal(principal_field: dict | str) -> bool:
    """Check if a policy Principal field contains ``sso.amazonaws.com``."""
    if isinstance(principal_field, str):
        return principal_field == "sso.amazonaws.com"

    if isinstance(principal_field, dict):
        for key in ("Service", "AWS", "Federated"):
            value = principal_field.get(key)
            if value is None:
                continue
            if isinstance(value, str) and value == "sso.amazonaws.com":
                return True
            if isinstance(value, list) and "sso.amazonaws.com" in value:
                return True

    return False


def _find_oidc_provider(principal_field: dict | str) -> str | None:
    """Find an OIDC provider ARN in a policy Principal field.

    Returns the first matching ARN or ``None``.
    """
    if isinstance(principal_field, str):
        if _OIDC_PROVIDER_RE.match(principal_field):
            return principal_field
        return None

    if isinstance(principal_field, dict):
        # OIDC providers appear under the "Federated" key
        for key in ("Federated", "AWS", "Service"):
            value = principal_field.get(key)
            if value is None:
                continue
            if isinstance(value, str):
                if _OIDC_PROVIDER_RE.match(value):
                    return value
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and _OIDC_PROVIDER_RE.match(item):
                        return item

    return None
