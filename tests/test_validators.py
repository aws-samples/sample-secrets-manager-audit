"""Unit tests for secrets_audit.validators."""

from __future__ import annotations

import pytest
import click

from secrets_audit.validators import (
    validate_secret_input,
    validate_account_id,
    validate_role_arn,
)


# ---------------------------------------------------------------------------
# validate_secret_input
# ---------------------------------------------------------------------------


class TestValidateSecretInput:
    """Tests for validate_secret_input."""

    def test_accepts_simple_secret_name(self) -> None:
        assert validate_secret_input("my-secret") == "my-secret"

    def test_accepts_hierarchical_path(self) -> None:
        assert validate_secret_input("rds/prod-db-west/app_user") == "rds/prod-db-west/app_user"

    def test_accepts_name_with_special_chars(self) -> None:
        assert validate_secret_input("key+=.@name") == "key+=.@name"

    def test_accepts_valid_arn(self) -> None:
        arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-AbCdEf"
        assert validate_secret_input(arn) == arn

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_secret_input("")

    def test_rejects_string_with_spaces(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_secret_input("my secret")

    def test_rejects_arn_with_invalid_region(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_secret_input("arn:aws:secretsmanager:INVALID:123456789012:secret:my-secret-AbCdEf")

    def test_rejects_special_characters(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_secret_input("secret!name")


# ---------------------------------------------------------------------------
# validate_account_id
# ---------------------------------------------------------------------------


class TestValidateAccountId:
    """Tests for validate_account_id."""

    def test_accepts_none(self) -> None:
        assert validate_account_id(None) is None

    def test_accepts_valid_12_digit_id(self) -> None:
        assert validate_account_id("123456789012") == "123456789012"

    def test_rejects_short_id(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_account_id("12345678901")

    def test_rejects_long_id(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_account_id("1234567890123")

    def test_rejects_non_numeric(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_account_id("12345678901a")

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_account_id("")


# ---------------------------------------------------------------------------
# validate_role_arn
# ---------------------------------------------------------------------------


class TestValidateRoleArn:
    """Tests for validate_role_arn."""

    def test_accepts_none(self) -> None:
        assert validate_role_arn(None) is None

    def test_accepts_valid_role_arn(self) -> None:
        arn = "arn:aws:iam::123456789012:role/MyRole"
        assert validate_role_arn(arn) == arn

    def test_accepts_role_with_path(self) -> None:
        arn = "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_Admin_abc123"
        assert validate_role_arn(arn) == arn

    def test_rejects_user_arn(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_role_arn("arn:aws:iam::123456789012:user/MyUser")

    def test_rejects_malformed_arn(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_role_arn("not-an-arn")

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(click.BadParameter):
            validate_role_arn("")


# ---------------------------------------------------------------------------
# Property-based tests (hypothesis)
# ---------------------------------------------------------------------------

import re
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from secrets_audit.validators import (
    SECRET_NAME_PATTERN,
    SECRET_ARN_PATTERN,
    ACCOUNT_ID_PATTERN,
    ROLE_ARN_PATTERN,
)

# Shared character sets matching the validator regex patterns
_SECRET_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_+=.@-"
_ALNUM_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_LOWER_ALNUM_DASH = "abcdefghijklmnopqrstuvwxyz0123456789-"

# Strategies for generating valid inputs
_valid_secret_names = st.text(alphabet=_SECRET_NAME_CHARS, min_size=1, max_size=64)

_valid_regions = st.sampled_from([
    "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ca-central-1",
])

_valid_account_ids = st.from_regex(r"\d{12}", fullmatch=True)

_valid_secret_arns = st.builds(
    lambda region, acct, name, suffix: f"arn:aws:secretsmanager:{region}:{acct}:secret:{name}-{suffix}",
    region=_valid_regions,
    acct=_valid_account_ids,
    name=st.text(alphabet=_SECRET_NAME_CHARS, min_size=1, max_size=32),
    suffix=st.text(alphabet=_ALNUM_CHARS, min_size=6, max_size=6),
)

_valid_role_arns = st.builds(
    lambda acct, name: f"arn:aws:iam::{acct}:role/{name}",
    acct=_valid_account_ids,
    name=st.text(alphabet=_SECRET_NAME_CHARS, min_size=1, max_size=32),
)


# Feature: secrets-audit-tool, Property 4: Input validation accepts valid inputs and rejects invalid inputs
class TestProperty4InputValidation:
    """Property 4: Input validation accepts valid inputs and rejects invalid inputs.

    **Validates: Requirements 1.11, 2.15**
    """

    @given(name=_valid_secret_names)
    @settings(max_examples=100)
    def test_validate_secret_input_accepts_valid_names(self, name: str) -> None:
        # Feature: secrets-audit-tool, Property 4: Input validation accepts valid inputs and rejects invalid inputs
        assert validate_secret_input(name) == name

    @given(arn=_valid_secret_arns)
    @settings(max_examples=100)
    def test_validate_secret_input_accepts_valid_arns(self, arn: str) -> None:
        # Feature: secrets-audit-tool, Property 4: Input validation accepts valid inputs and rejects invalid inputs
        assert validate_secret_input(arn) == arn

    @given(value=st.text())
    @settings(max_examples=100)
    def test_validate_secret_input_rejects_invalid_strings(self, value: str) -> None:
        # Feature: secrets-audit-tool, Property 4: Input validation accepts valid inputs and rejects invalid inputs
        assume(not SECRET_NAME_PATTERN.match(value))
        assume(not SECRET_ARN_PATTERN.match(value))
        with pytest.raises(click.BadParameter):
            validate_secret_input(value)

    @given(acct=_valid_account_ids)
    @settings(max_examples=100)
    def test_validate_account_id_accepts_valid_ids(self, acct: str) -> None:
        # Feature: secrets-audit-tool, Property 4: Input validation accepts valid inputs and rejects invalid inputs
        assert validate_account_id(acct) == acct

    @given(value=st.text())
    @settings(max_examples=100)
    def test_validate_account_id_rejects_invalid_strings(self, value: str) -> None:
        # Feature: secrets-audit-tool, Property 4: Input validation accepts valid inputs and rejects invalid inputs
        assume(not ACCOUNT_ID_PATTERN.match(value))
        with pytest.raises(click.BadParameter):
            validate_account_id(value)

    @given(arn=_valid_role_arns)
    @settings(max_examples=100)
    def test_validate_role_arn_accepts_valid_arns(self, arn: str) -> None:
        # Feature: secrets-audit-tool, Property 4: Input validation accepts valid inputs and rejects invalid inputs
        assert validate_role_arn(arn) == arn

    @given(value=st.text())
    @settings(max_examples=100)
    def test_validate_role_arn_rejects_invalid_strings(self, value: str) -> None:
        # Feature: secrets-audit-tool, Property 4: Input validation accepts valid inputs and rejects invalid inputs
        assume(not ROLE_ARN_PATTERN.match(value))
        with pytest.raises(click.BadParameter):
            validate_role_arn(value)
