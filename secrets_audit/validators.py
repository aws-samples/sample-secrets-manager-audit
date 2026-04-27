"""Input validation functions for secrets-audit CLI.

All user-supplied CLI inputs (secret name, ARN, account ID, role ARN) are
validated here before use in any API calls.  Validators return the validated
string on success or raise ``click.BadParameter`` with a descriptive message
on invalid input.
"""

from __future__ import annotations

import re

import click

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

SECRET_NAME_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9/_+=.@-]+$")
SECRET_ARN_PATTERN: re.Pattern[str] = re.compile(
    r"^arn:aws:secretsmanager:[a-z0-9-]+:\d{12}:secret:[a-zA-Z0-9/_+=.@-]+-[a-zA-Z0-9]{6}$"
)
ACCOUNT_ID_PATTERN: re.Pattern[str] = re.compile(r"^\d{12}$")
REGION_PATTERN: re.Pattern[str] = re.compile(r"^[a-z]{2,4}(-[a-z]+-\d{1,2}){1}$")
ROLE_ARN_PATTERN: re.Pattern[str] = re.compile(
    r"^arn:aws:iam::\d{12}:role/[a-zA-Z0-9/_+=.@-]+$"
)
PROFILE_NAME_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_-]+$")


# ---------------------------------------------------------------------------
# Validator functions
# ---------------------------------------------------------------------------


def validate_secret_input(value: str) -> str:
    """Validate a secret name or full Secrets Manager ARN.

    Returns the validated string unchanged.  Raises ``click.BadParameter``
    if *value* matches neither a valid secret name nor a valid secret ARN.
    """
    if SECRET_ARN_PATTERN.match(value) or SECRET_NAME_PATTERN.match(value):
        return value
    raise click.BadParameter(
        f"Invalid secret identifier: '{value}'. "
        "Must be a valid secret name (alphanumeric, /, _, +, =, ., @, -) "
        "or a full Secrets Manager ARN."
    )


def validate_account_id(value: str | None) -> str | None:
    """Validate a 12-digit AWS account ID.

    Accepts ``None`` (the parameter is optional) and returns ``None`` in that
    case.  Raises ``click.BadParameter`` if *value* is not a 12-digit numeric
    string.
    """
    if value is None:
        return None
    if ACCOUNT_ID_PATTERN.match(value):
        return value
    raise click.BadParameter(
        f"Invalid AWS account ID: '{value}'. Must be a 12-digit numeric string."
    )


def validate_role_arn(value: str | None) -> str | None:
    """Validate an IAM role ARN.

    Accepts ``None`` (the parameter is optional) and returns ``None`` in that
    case.  Raises ``click.BadParameter`` if *value* does not match the
    expected IAM role ARN format.
    """
    if value is None:
        return None
    if ROLE_ARN_PATTERN.match(value):
        return value
    raise click.BadParameter(
        f"Invalid IAM role ARN: '{value}'. "
        "Expected format: arn:aws:iam::<account-id>:role/<role-name>"
    )


def validate_region(value: str | None) -> str | None:
    """Validate an AWS region code.

    Accepts ``None`` (the parameter is optional) and returns ``None`` in that
    case.  Raises ``click.BadParameter`` if *value* does not match the
    expected AWS region format (e.g. ``us-east-1``, ``ap-southeast-1``).
    """
    if value is None:
        return None
    if REGION_PATTERN.match(value):
        return value
    raise click.BadParameter(
        f"Invalid AWS region: '{value}'. "
        "Expected format: <partition>-<geo>-<number> (e.g. us-east-1, eu-west-2)."
    )


def validate_profile_name(value: str | None) -> str | None:
    """Validate an AWS CLI profile name.

    Accepts ``None`` (the parameter is optional) and returns ``None`` in that
    case.  Raises ``click.BadParameter`` if *value* does not match the
    expected profile name format (alphanumeric, underscore, hyphen).
    """
    if value is None:
        return None
    if PROFILE_NAME_PATTERN.match(value):
        return value
    raise click.BadParameter(
        f"Invalid profile name: '{value}'. "
        "Must contain only alphanumeric characters, underscores, or hyphens."
    )
