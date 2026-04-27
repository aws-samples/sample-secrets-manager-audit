"""boto3 session and client factory for secrets-audit.

Provides helpers to create production-account sessions, assume cross-account
roles for Identity Center resolution, and retrieve the operator's caller
identity.  All sessions use explicit region parameters and adaptive retry.

Credentials are **never** written to disk, logs, or output — only temporary
STS credentials are used for cross-account calls.
"""

from __future__ import annotations

import logging
from datetime import datetime

import boto3
import botocore.exceptions
from boto3 import Session
from botocore.config import Config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Retry configuration — adaptive mode with up to 5 attempts
# ---------------------------------------------------------------------------

RETRY_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class CrossAccountError(Exception):
    """Raised when cross-account role assumption fails."""


class ProfileSessionError(Exception):
    """Raised when session creation from a named profile fails."""


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------


def create_prod_session(region: str | None = None) -> Session:
    """Create a boto3 session for the production account.

    Parameters
    ----------
    region:
        AWS region name (e.g. ``"us-east-1"``).  Passed through to the
        session so every client created from it uses an explicit region.
    """
    return boto3.Session(region_name=region)


def create_cross_account_session(
    prod_session: Session,
    role_arn: str,
    session_name: str = "secrets-audit-session",
    region: str | None = None,
) -> Session:
    """Assume a cross-account role and return a new session with temporary credentials.

    Uses ``sts:AssumeRole`` to obtain short-lived credentials scoped to the
    target role.  On success the caller receives a fresh :class:`boto3.Session`
    backed by those temporary credentials.

    Parameters
    ----------
    prod_session:
        An existing session in the production account (used to call STS).
    role_arn:
        The IAM role ARN to assume in the master account.
    session_name:
        STS session name attached to the assumed-role session.
    region:
        AWS region for the new session.

    Raises
    ------
    CrossAccountError
        If the ``AssumeRole`` call fails for any reason (permission denied,
        nonexistent role, MFA requirement, connectivity, etc.).
    """
    sts = prod_session.client("sts", config=RETRY_CONFIG)

    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
        )
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        logger.warning(
            "AssumeRole failed for %s (ClientError %s): %s",
            role_arn,
            error_code,
            exc,
        )
        raise CrossAccountError(
            f"Unable to assume cross-account role {role_arn}: {error_code}"
        ) from exc
    except botocore.exceptions.BotoCoreError as exc:
        logger.warning(
            "AssumeRole failed for %s (BotoCoreError): %s",
            role_arn,
            exc,
        )
        raise CrossAccountError(
            f"Unable to assume cross-account role {role_arn}: {exc}"
        ) from exc

    creds = response["Credentials"]
    logger.info("Cross-account assumption succeeded for role %s", role_arn)

    # Build a new session from the temporary credentials.
    # Credentials are only held in memory — never persisted.
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def create_profile_session(profile_name: str) -> Session:
    """Create a boto3 session from a named AWS CLI profile.

    Builds a session using the given profile name and eagerly validates it
    by calling ``sts:GetCallerIdentity``.  This catches configuration and
    credential problems early, before the session is handed to the Identity
    Center resolution pipeline.

    Parameters
    ----------
    profile_name:
        The named AWS CLI profile (from ``~/.aws/config`` or
        ``~/.aws/credentials``) to use for the session.

    Returns
    -------
    Session
        A validated boto3 session backed by the named profile.

    Raises
    ------
    ProfileSessionError
        If the profile does not exist, the credentials are invalid/expired,
        or the STS validation call fails for any reason.
    """
    try:
        session = boto3.Session(profile_name=profile_name)
    except botocore.exceptions.ProfileNotFound as exc:
        logger.warning(
            "Profile %r not found in AWS configuration: %s",
            profile_name,
            exc,
        )
        raise ProfileSessionError(
            f"AWS profile {profile_name!r} not found in configuration"
        ) from exc

    sts = session.client("sts", config=RETRY_CONFIG)

    try:
        sts.get_caller_identity()
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        logger.warning(
            "Profile %r STS validation failed (ClientError %s): %s",
            profile_name,
            error_code,
            exc,
        )
        raise ProfileSessionError(
            f"Profile {profile_name!r} credentials are invalid: {error_code}"
        ) from exc
    except botocore.exceptions.BotoCoreError as exc:
        logger.warning(
            "Profile %r STS validation failed (BotoCoreError): %s",
            profile_name,
            exc,
        )
        raise ProfileSessionError(
            f"Profile {profile_name!r} STS validation failed: {exc}"
        ) from exc

    logger.info("Profile session validated for %r", profile_name)
    return session


def get_caller_identity(session: Session) -> str:
    """Return the ARN of the current caller (operator identity).

    Calls ``sts:GetCallerIdentity`` and returns the ``Arn`` field, which may
    be an IAM user ARN or an assumed-role ARN depending on how the operator
    authenticated.

    Parameters
    ----------
    session:
        The boto3 session whose identity should be resolved.
    """
    sts = session.client("sts", config=RETRY_CONFIG)

    try:
        response = sts.get_caller_identity()
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        logger.error("GetCallerIdentity failed (ClientError %s): %s", error_code, exc)
        raise
    except botocore.exceptions.BotoCoreError as exc:
        logger.error("GetCallerIdentity failed (BotoCoreError): %s", exc)
        raise

    arn: str = response["Arn"]
    logger.debug("Caller identity resolved: %s", arn)
    return arn


# ---------------------------------------------------------------------------
# Credential expiry helpers
# ---------------------------------------------------------------------------

_EXPIRED_TOKEN_CODES = frozenset({"ExpiredTokenException", "ExpiredToken", "RequestExpired"})


def get_credential_expiry(session: Session) -> datetime | None:
    """Return the expiry time of the session's credentials, or None if unknown.

    For refreshable credentials (SSO, instance profiles, assumed roles),
    boto3's credential resolver exposes an _expiry_datetime attribute.
    For static credentials (environment variables), no expiry is available.

    This function never makes API calls. It only reads in-memory metadata.
    """
    try:
        credentials = session.get_credentials()
        if credentials is None:
            return None
        # RefreshableCredentials have _expiry_datetime
        resolved = credentials.get_frozen_credentials()
        # The underlying credentials object (before freezing) may have expiry
        inner = getattr(credentials, '_credentials', credentials)
        expiry = getattr(inner, '_expiry_datetime', None)
        if expiry is not None:
            return expiry
        return None
    except Exception:
        return None


def is_expired_token_error(exc: botocore.exceptions.ClientError) -> bool:
    """Return True if the ClientError is an expired-token error."""
    return exc.response["Error"]["Code"] in _EXPIRED_TOKEN_CODES
