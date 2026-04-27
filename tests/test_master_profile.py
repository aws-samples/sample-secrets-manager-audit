"""Property-based and unit tests for the master-profile feature."""

from __future__ import annotations

import re

import click
import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from secrets_audit.validators import PROFILE_NAME_PATTERN, validate_profile_name

# ---------------------------------------------------------------------------
# Property 1: Profile name validation accepts valid and rejects invalid
# Feature: master-profile, Property 1: Profile name validation accepts valid and rejects invalid
# ---------------------------------------------------------------------------


class TestProperty1ProfileNameValidation:
    """Property 1: Profile name validation accepts valid and rejects invalid.

    **Validates: Requirements 3.1, 3.2, 3.3**
    """

    @given(name=st.from_regex(r"[a-zA-Z0-9_-]+", fullmatch=True))
    @settings(max_examples=100)
    def test_validate_profile_name_accepts_valid_names(self, name: str) -> None:
        """Valid profile names matching PROFILE_NAME_PATTERN are returned unchanged."""
        # Feature: master-profile, Property 1: Profile name validation accepts valid and rejects invalid
        assert PROFILE_NAME_PATTERN.match(name), f"Strategy bug: {name!r} doesn't match pattern"
        assert validate_profile_name(name) == name

    @given(value=st.text())
    @settings(max_examples=100)
    def test_validate_profile_name_rejects_invalid_strings(self, value: str) -> None:
        """Arbitrary strings that do NOT match PROFILE_NAME_PATTERN raise click.BadParameter."""
        # Feature: master-profile, Property 1: Profile name validation accepts valid and rejects invalid
        assume(not PROFILE_NAME_PATTERN.match(value))
        with pytest.raises(click.BadParameter):
            validate_profile_name(value)


# ---------------------------------------------------------------------------
# Unit tests: Profile name validation edge cases
# ---------------------------------------------------------------------------


class TestProfileNameValidationEdgeCases:
    """Unit tests for profile name validation edge cases.

    **Validates: Requirements 3.1, 3.2, 3.3**
    """

    def test_none_returns_none(self) -> None:
        """validate_profile_name(None) returns None."""
        assert validate_profile_name(None) is None

    def test_empty_string_rejected(self) -> None:
        """validate_profile_name('') raises click.BadParameter."""
        with pytest.raises(click.BadParameter):
            validate_profile_name("")


# ---------------------------------------------------------------------------
# Unit tests: create_profile_session()
# ---------------------------------------------------------------------------

from unittest.mock import MagicMock, patch

import botocore.exceptions

from secrets_audit.aws_clients import ProfileSessionError, create_profile_session


class TestCreateProfileSession:
    """Unit tests for create_profile_session().

    **Validates: Requirements 4.1, 4.2**
    """

    @patch("secrets_audit.aws_clients.boto3.Session")
    def test_profile_not_found_raises_profile_session_error(
        self, mock_session_cls: MagicMock
    ) -> None:
        """ProfileNotFound from boto3.Session is wrapped in ProfileSessionError."""
        mock_session_cls.side_effect = botocore.exceptions.ProfileNotFound(
            profile="nonexistent"
        )

        with pytest.raises(ProfileSessionError, match="not found"):
            create_profile_session("nonexistent")

    @patch("secrets_audit.aws_clients.boto3.Session")
    def test_expired_credentials_raises_profile_session_error(
        self, mock_session_cls: MagicMock
    ) -> None:
        """ClientError from sts.get_caller_identity (expired creds) is wrapped in ProfileSessionError."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        client_error = botocore.exceptions.ClientError(
            {"Error": {"Code": "ExpiredTokenException", "Message": "Token expired"}},
            "GetCallerIdentity",
        )
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = client_error
        mock_session.client.return_value = mock_sts

        with pytest.raises(ProfileSessionError, match="invalid"):
            create_profile_session("expired-profile")

    @patch("secrets_audit.aws_clients.boto3.Session")
    def test_successful_session_returned(self, mock_session_cls: MagicMock) -> None:
        """Successful session creation and STS validation returns the session."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "UserId": "AIDEXAMPLE",
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test-user",
        }
        mock_session.client.return_value = mock_sts

        result = create_profile_session("valid-profile")

        assert result is mock_session
        mock_session_cls.assert_called_once_with(profile_name="valid-profile")
        mock_sts.get_caller_identity.assert_called_once()


# ---------------------------------------------------------------------------
# Property 2: Mutual exclusivity of --master-profile with cross-account flags
# Feature: master-profile, Property 2: Mutual exclusivity of --master-profile with cross-account flags
# ---------------------------------------------------------------------------

import json

from click.testing import CliRunner

from secrets_audit.cli import main
from secrets_audit.models import (
    AccessLevel,
    IdentityCenterResolution,
    PrincipalAccess,
    PrincipalClassification,
    PrincipalType,
    SecretMetadata,
)
from secrets_audit.resolver import SimulationResult

# Strategies for generating valid 12-digit account IDs and role ARNs
_valid_profile_names = st.from_regex(r"[a-zA-Z0-9_-]+", fullmatch=True)
_valid_account_ids = st.from_regex(r"\d{12}", fullmatch=True)
_valid_role_arns = st.builds(
    lambda acct, name: f"arn:aws:iam::{acct}:role/{name}",
    acct=_valid_account_ids,
    name=st.from_regex(r"[a-zA-Z0-9/_+=.@-]+", fullmatch=True).filter(lambda s: len(s) > 0),
)


class TestProperty2MutualExclusivity:
    """Property 2: Mutual exclusivity of --master-profile with cross-account flags.

    **Validates: Requirements 2.1, 2.2, 2.3**
    """

    @given(
        profile=_valid_profile_names,
        account_id=_valid_account_ids,
    )
    @settings(max_examples=100)
    def test_master_profile_with_account_id_is_rejected(
        self, profile: str, account_id: str
    ) -> None:
        """--master-profile + --master-account-id produces non-zero exit and 'mutually exclusive' message."""
        # Feature: master-profile, Property 2: Mutual exclusivity of --master-profile with cross-account flags
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--secret", "test/secret",
                "--master-profile", profile,
                "--master-account-id", account_id,
            ],
        )
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output.lower()

    @given(
        profile=_valid_profile_names,
        role_arn=_valid_role_arns,
    )
    @settings(max_examples=100)
    def test_master_profile_with_role_arn_is_rejected(
        self, profile: str, role_arn: str
    ) -> None:
        """--master-profile + --cross-account-role-arn produces non-zero exit and 'mutually exclusive' message."""
        # Feature: master-profile, Property 2: Mutual exclusivity of --master-profile with cross-account flags
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--secret", "test/secret",
                "--master-profile", profile,
                "--cross-account-role-arn", role_arn,
            ],
        )
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output.lower()

    @given(
        profile=_valid_profile_names,
        account_id=_valid_account_ids,
        role_arn=_valid_role_arns,
    )
    @settings(max_examples=100)
    def test_master_profile_with_both_flags_is_rejected(
        self, profile: str, account_id: str, role_arn: str
    ) -> None:
        """--master-profile + both cross-account flags produces non-zero exit and 'mutually exclusive' message."""
        # Feature: master-profile, Property 2: Mutual exclusivity of --master-profile with cross-account flags
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--secret", "test/secret",
                "--master-profile", profile,
                "--master-account-id", account_id,
                "--cross-account-role-arn", role_arn,
            ],
        )
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output.lower()


# ---------------------------------------------------------------------------
# Property 3: Profile failure produces partial IC resolution
# Feature: master-profile, Property 3: Profile failure produces partial IC resolution
# ---------------------------------------------------------------------------

# Strategy: generate valid permission set names (alphanumeric + hyphens, 1-20 chars)
_valid_ps_names = st.from_regex(r"[a-zA-Z][a-zA-Z0-9-]{0,19}", fullmatch=True)


def _build_ic_principal(ps_name: str) -> PrincipalAccess:
    """Build an IC-classified PrincipalAccess with a role name following the SSO pattern."""
    role_name = f"AWSReservedSSO_{ps_name}_1234abcd5678"
    return PrincipalAccess(
        principal_type=PrincipalType.IAM_ROLE,
        principal_arn=f"arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/{role_name}",
        principal_name=role_name,
        access_level=AccessLevel.READ,
        classification=PrincipalClassification.IDENTITY_CENTER,
        policy_source="identity_policy",
    )


class TestProperty3ProfileFailurePartialIC:
    """Property 3: Profile failure produces partial IC resolution.

    **Validates: Requirements 4.1, 4.2, 4.3**
    """

    @given(ps_name=_valid_ps_names)
    @settings(max_examples=100)
    def test_profile_failure_sets_partial_ic(self, ps_name: str) -> None:
        """When create_profile_session raises ProfileSessionError, IC principals get ic_partial=True
        and permission_set_name matches the generated name."""
        # Feature: master-profile, Property 3: Profile failure produces partial IC resolution
        ic_principal = _build_ic_principal(ps_name)

        mock_session = MagicMock()
        mock_session.region_name = "us-east-1"

        runner = CliRunner(mix_stderr=False)
        with (
            patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value="bad-profile"),
            patch("secrets_audit.cli.create_prod_session", return_value=mock_session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(
                name="test/secret",
                arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
            )),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[ic_principal])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _sess, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_profile_session",
                side_effect=ProfileSessionError("Profile session failed"),
            ),
        ):
            result = runner.invoke(
                main,
                ["--secret", "test/secret", "--master-profile", "bad-profile", "--output", "json", "--allow-partial"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        parsed = json.loads(result.output)

        # Find the IC principal in the output
        ic_principals = [
            p for p in parsed["principals"]
            if p.get("ic_partial") is True
        ]
        assert len(ic_principals) == 1, f"Expected 1 IC partial principal, got {len(ic_principals)}"
        assert ic_principals[0]["permission_set_name"] == ps_name


# ---------------------------------------------------------------------------
# Unit tests: CLI --master-profile wiring
# ---------------------------------------------------------------------------


def _build_ic_principal_for_unit(ps_name: str) -> PrincipalAccess:
    """Build an IC-classified PrincipalAccess for unit tests."""
    role_name = f"AWSReservedSSO_{ps_name}_1234abcd5678"
    return PrincipalAccess(
        principal_type=PrincipalType.IAM_ROLE,
        principal_arn=f"arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/{role_name}",
        principal_name=role_name,
        access_level=AccessLevel.READ,
        classification=PrincipalClassification.IDENTITY_CENTER,
        policy_source="identity_policy",
    )


class TestCliMasterProfileWiring:
    """Unit tests for CLI --master-profile option wiring.

    **Validates: Requirements 1.2, 1.3, 1.4, 4.1, 4.2, 5.1, 5.2, 6.3**
    """

    def test_help_contains_master_profile_option(self) -> None:
        """--help output lists --master-profile with description mentioning 'mutually exclusive'."""
        # Validates: Requirements 5.1, 5.2
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--master-profile" in result.output
        assert "mutually exclusive" in result.output.lower() or "Mutually exclusive" in result.output

    def test_master_profile_calls_create_profile_session(self) -> None:
        """CLI with only --master-profile calls create_profile_session and passes result to IC resolution."""
        # Validates: Requirements 1.2, 1.3
        ic_principal = _build_ic_principal_for_unit("AdminAccess")

        mock_session = MagicMock()
        mock_session.region_name = "us-east-1"
        mock_profile_session = MagicMock()

        runner = CliRunner()
        with (
            patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value="mgmt-profile"),
            patch("secrets_audit.cli.create_prod_session", return_value=mock_session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(
                name="test/secret",
                arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
            )),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[ic_principal])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _sess, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_profile_session",
                return_value=mock_profile_session,
            ) as mock_create_profile,
            patch("secrets_audit.cli.resolve_identity_center") as mock_resolve_ic,
        ):
            mock_resolve_ic.return_value = IdentityCenterResolution(
                permission_set_name="AdminAccess",
            )
            result = runner.invoke(
                main,
                ["--secret", "test/secret", "--master-profile", "mgmt-profile"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        mock_create_profile.assert_called_once_with("mgmt-profile")
        # resolve_identity_center should be called with the profile session
        mock_resolve_ic.assert_called_once()
        call_args = mock_resolve_ic.call_args
        assert call_args[0][0] is mock_profile_session

    def test_no_master_profile_does_not_call_create_profile_session(self) -> None:
        """CLI without --master-profile does not call create_profile_session."""
        # Validates: Requirement 1.4
        mock_session = MagicMock()
        mock_session.region_name = "us-east-1"

        runner = CliRunner()
        with (
            patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=mock_session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(
                name="test/secret",
                arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
            )),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch("secrets_audit.cli.create_profile_session") as mock_create_profile,
        ):
            result = runner.invoke(main, ["--secret", "test/secret"])

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        mock_create_profile.assert_not_called()

    def test_profile_session_not_passed_to_non_ic_functions(self) -> None:
        """Profile session is not passed to Secrets Manager, IAM, or CloudTrail calls (they use prod_session)."""
        # Validates: Requirement 6.3
        mock_prod_session = MagicMock()
        mock_prod_session.region_name = "us-east-1"
        mock_profile_session = MagicMock()

        runner = CliRunner()
        with (
            patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value="mgmt-profile"),
            patch("secrets_audit.cli.create_prod_session", return_value=mock_prod_session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester") as mock_identity,
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(
                name="test/secret",
                arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
            )) as mock_resolve_secret,
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]) as mock_resource_policy,
            patch("secrets_audit.cli.list_iam_roles", return_value=[]) as mock_list_roles,
            patch("secrets_audit.cli.list_iam_users", return_value=[]) as mock_list_users,
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])) as mock_simulate,
            patch("secrets_audit.cli.get_last_accessed", return_value={}) as mock_cloudtrail,
            patch("secrets_audit.cli.create_profile_session", return_value=mock_profile_session),
        ):
            result = runner.invoke(
                main,
                ["--secret", "test/secret", "--master-profile", "mgmt-profile", "--last-accessed"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # All non-IC functions should receive prod_session, NOT profile_session
        mock_identity.assert_called_once_with(mock_prod_session)
        mock_resolve_secret.assert_called_once_with(mock_prod_session, "test/secret")
        mock_resource_policy.assert_called_once_with(mock_prod_session, "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf")
        mock_list_roles.assert_called_once_with(mock_prod_session)
        mock_list_users.assert_called_once_with(mock_prod_session)
        mock_simulate.assert_called_once()
        assert mock_simulate.call_args[0][0] is mock_prod_session
        mock_cloudtrail.assert_called_once()
        assert mock_cloudtrail.call_args[0][0] is mock_prod_session

    def test_profile_failure_adds_warning_to_report(self) -> None:
        """CLI with --master-profile and profile failure adds warning to report JSON output."""
        # Validates: Requirements 4.1, 4.2
        mock_session = MagicMock()
        mock_session.region_name = "us-east-1"

        runner = CliRunner(mix_stderr=False)
        with (
            patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value="bad-profile"),
            patch("secrets_audit.cli.create_prod_session", return_value=mock_session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(
                name="test/secret",
                arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
            )),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_profile_session",
                side_effect=ProfileSessionError("Profile session failed"),
            ),
        ):
            result = runner.invoke(
                main,
                ["--secret", "test/secret", "--master-profile", "bad-profile", "--output", "json", "--allow-partial"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        parsed = json.loads(result.output)
        assert len(parsed["warnings"]) > 0
        warning_text = " ".join(parsed["warnings"]).lower()
        assert "profile" in warning_text or "bad-profile" in warning_text
