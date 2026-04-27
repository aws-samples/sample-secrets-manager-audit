"""CloudTrail last-accessed enrichment.

Queries CloudTrail ``LookupEvents`` for ``secretsmanager:GetSecretValue``
events to determine when each principal last accessed a target secret.

**Security invariant**: this module only calls ``cloudtrail:LookupEvents``
(a read-only API).  It never calls ``secretsmanager:GetSecretValue`` itself
— it only inspects CloudTrail records of *other* callers who did.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Callable

import botocore.exceptions
from boto3 import Session

from secrets_audit.aws_clients import RETRY_CONFIG

logger = logging.getLogger(__name__)

# Status strings returned when a datetime is not available
NO_RECENT_ACCESS = "No recent access (>90 days)"
CLOUDTRAIL_UNAVAILABLE = "Unknown (CloudTrail unavailable)"
CREDENTIALS_EXPIRED = "Unknown (credentials expired)"


def get_last_accessed(
    session: Session,
    secret_arn: str,
    principal_arns: list[str],
    lookback_days: int = 90,
    progress: Callable[[str], None] | None = None,
) -> dict[str, datetime | str]:
    """Query CloudTrail for the most recent ``GetSecretValue`` event per principal.

    Parameters
    ----------
    session:
        A boto3 session for the production account.
    secret_arn:
        The full ARN of the target secret.
    principal_arns:
        The list of principal ARNs to look up.
    lookback_days:
        How many days back to search (default 90).

    Returns
    -------
    dict[str, datetime | str]
        A mapping of *every* requested principal ARN to one of:

        * :class:`datetime` — the most recent access timestamp
        * ``"No recent access (>90 days)"`` — no events in the window
        * ``"Unknown (CloudTrail unavailable)"`` — API inaccessible
    """
    # Fast path: nothing to look up
    if not principal_arns:
        return {}

    try:
        events = _fetch_events(session, secret_arn, lookback_days, progress=progress)
    except _CloudTrailUnavailable:
        return {arn: CLOUDTRAIL_UNAVAILABLE for arn in principal_arns}

    # Build a lookup of the most recent timestamp per role name.
    # CloudTrail records assumed-role session ARNs like:
    #   arn:aws:sts::ACCT:assumed-role/ROLE_NAME/SESSION
    # But the principal list uses IAM role ARNs like:
    #   arn:aws:iam::ACCT:role/PATH/ROLE_NAME
    # We normalize both to the bare role name for matching.
    latest: dict[str, datetime] = {}
    for event in events:
        event_principal = _extract_principal_arn(event)
        event_time = event.get("EventTime")
        if event_principal is None or event_time is None:
            continue

        role_key = _normalize_role_name(event_principal)

        # Track the maximum timestamp per normalized role name
        if role_key in latest:
            if event_time > latest[role_key]:
                latest[role_key] = event_time
        else:
            latest[role_key] = event_time

    # Map every requested principal to a result using normalized matching
    result: dict[str, datetime | str] = {}
    for arn in principal_arns:
        role_key = _normalize_role_name(arn)
        if role_key in latest:
            result[arn] = latest[role_key]
        else:
            result[arn] = NO_RECENT_ACCESS

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _CloudTrailUnavailable(Exception):
    """Raised internally when CloudTrail cannot be queried."""


def _fetch_events(
    session: Session,
    secret_arn: str,
    lookback_days: int,
    progress: Callable[[str], None] | None = None,
) -> list[dict]:
    """Call ``LookupEvents`` with pagination to retrieve GetSecretValue events.

    Raises
    ------
    _CloudTrailUnavailable
        On ``AccessDeniedException`` or any connectivity / SDK error.
    """
    client = session.client("cloudtrail", config=RETRY_CONFIG)
    start_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    events: list[dict] = []
    next_token: str | None = None

    logger.info(
        "Querying CloudTrail events for resource %s (last %d days)",
        secret_arn,
        lookback_days,
    )

    try:
        while True:
            kwargs: dict = {
                "LookupAttributes": [
                    {
                        "AttributeKey": "ResourceName",
                        "AttributeValue": secret_arn,
                    }
                ],
                "StartTime": start_time,
                "MaxResults": 50,
            }
            if next_token is not None:
                kwargs["NextToken"] = next_token

            response = client.lookup_events(**kwargs)
            events.extend(response.get("Events", []))

            if progress:
                progress(f"Fetching CloudTrail events... {len(events)} events retrieved")

            next_token = response.get("NextToken")
            if not next_token:
                break

    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "AccessDeniedException":
            logger.warning(
                "CloudTrail access denied: %s. "
                "Last-accessed data will be unavailable.",
                exc,
            )
        else:
            logger.warning(
                "CloudTrail ClientError %s: %s. "
                "Last-accessed data will be unavailable.",
                error_code,
                exc,
            )
        raise _CloudTrailUnavailable(str(exc)) from exc
    except botocore.exceptions.BotoCoreError as exc:
        logger.warning(
            "CloudTrail connectivity/SDK error: %s. "
            "Last-accessed data will be unavailable.",
            exc,
        )
        raise _CloudTrailUnavailable(str(exc)) from exc

    events = [e for e in events if e.get("EventName") == "GetSecretValue"]
    logger.debug("Retrieved %d CloudTrail events", len(events))
    return events


def _normalize_role_name(arn: str) -> str:
    """Extract a bare role name from various ARN formats for matching.

    Handles:
    - IAM role ARN: ``arn:aws:iam::ACCT:role/PATH/ROLE_NAME`` → ``ROLE_NAME``
    - STS assumed-role ARN: ``arn:aws:sts::ACCT:assumed-role/ROLE_NAME/SESSION`` → ``ROLE_NAME``
    - IAM user ARN: ``arn:aws:iam::ACCT:user/USER_NAME`` → ``user/USER_NAME``
    - Anything else: returns the full ARN as-is (safe fallback)
    """
    # STS assumed-role: arn:aws:sts::ACCT:assumed-role/ROLE_NAME/SESSION
    if ":assumed-role/" in arn:
        parts = arn.split(":assumed-role/", 1)[1]
        return parts.split("/", 1)[0]

    # IAM role: arn:aws:iam::ACCT:role/[PATH/]ROLE_NAME
    if ":role/" in arn:
        role_path = arn.split(":role/", 1)[1]
        return role_path.rsplit("/", 1)[-1]

    # IAM user: arn:aws:iam::ACCT:user/USER_NAME — keep user/ prefix to avoid
    # collisions with roles that happen to share the same name
    if ":user/" in arn:
        return "user/" + arn.split(":user/", 1)[1]

    # Fallback: use the full ARN
    return arn


def _extract_principal_arn(event: dict) -> str | None:
    """Extract the principal ARN from a CloudTrail event.

    CloudTrail events contain a ``CloudTrailEvent`` field (JSON string)
    with ``userIdentity`` details.  We try, in order:

    1. ``userIdentity.arn`` from the parsed JSON (most reliable)
    2. The top-level ``Username`` field as a fallback

    Returns ``None`` if no principal can be determined.
    """
    # Try the embedded JSON first
    raw_event = event.get("CloudTrailEvent")
    if raw_event:
        try:
            parsed = json.loads(raw_event)
            user_identity = parsed.get("userIdentity", {})
            arn = user_identity.get("arn")
            if arn:
                return arn
        except (json.JSONDecodeError, TypeError):
            pass

    # Fallback to top-level Username (may be a role session name, not a full ARN)
    username = event.get("Username")
    if username and username.startswith("arn:"):
        return username

    return None
