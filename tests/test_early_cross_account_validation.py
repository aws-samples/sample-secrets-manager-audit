"""Property-based and unit tests for the early-cross-account-validation feature.

Tests cover:
- Property 1: Fail-fast exits with descriptive error
- Property 2: Fail-fast prevents expensive pipeline steps
- Property 3: Allow-partial continues with warning
- Property 4: Allow-partial produces partial IC resolution
- Property 5: Session reuse — single creation, same object
- Property 6: No session retry on allow-partial failure
- Property 7: Progress message emitted for early validation
- Property 8: Quiet flag suppresses early validation progress
- Unit tests for --allow-partial flag, call ordering, and error message format
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch, call

from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.aws_clients import CrossAccountError, ProfileSessionError
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

# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------

_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf"  # nosec B105
_SECRET_NAME = "test/secret"  # nosec B105
_ACCOUNT_ID = "987654321098"  # nosemgrep: generic.secrets.security.detected-aws-account-id
_ROLE_ARN = "arn:aws:iam::987654321098:role/cross-account-role"


def _mock_session() -> MagicMock:
    s = MagicMock()
    s.region_name = "us-east-1"
    return s


def _build_ic_principal(ps_name: str) -> PrincipalAccess:
    """Build an IC-classified principal with an AWSReservedSSO_ role name."""
    role_name = f"AWSReservedSSO_{ps_name}_1234abcd5678"
    return PrincipalAccess(
        principal_type=PrincipalType.IAM_ROLE,
        principal_arn=f"arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/{role_name}",
        principal_name=role_name,
        access_level=AccessLevel.READ,
        classification=PrincipalClassification.IDENTITY_CENTER,
        policy_source="identity_policy",
    )


def _pipeline_patches(
    mock_session: MagicMock,
    principals: list[PrincipalAccess] | None = None,
):
    """Return a tuple of patch context managers for the full CLI pipeline."""
    return (
        patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
        patch("secrets_audit.cli.validate_account_id", return_value=None),
        patch("secrets_audit.cli.validate_role_arn", return_value=None),
        patch("secrets_audit.cli.validate_region", return_value=None),
        patch("secrets_audit.cli.validate_profile_name", return_value=None),
        patch("secrets_audit.cli.create_prod_session", return_value=mock_session),
        patch(
            "secrets_audit.cli.get_caller_identity",
            return_value="arn:aws:iam::123456789012:user/tester",
        ),
        patch(
            "secrets_audit.cli.resolve_secret",
            return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN),
        ),
        patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
        patch("secrets_audit.cli.list_iam_roles", return_value=[]),
        patch("secrets_audit.cli.list_iam_users", return_value=[]),
        patch(
            "secrets_audit.cli.simulate_principal_access",
            return_value=SimulationResult(principals=principals or []),
        ),
        patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
        patch("secrets_audit.cli.get_last_accessed", return_value={}),
    )


# Hypothesis strategy for non-empty error messages
_error_messages = st.text(min_size=1, max_size=50).filter(lambda s: s.strip())


# ---------------------------------------------------------------------------
# Property 1: Fail-fast exits with descriptive error
# Feature: early-cross-account-validation, Property 1
# ---------------------------------------------------------------------------


class TestProperty1FailFastDescriptiveError:
    """Property 1: Fail-fast exits with descriptive error.

    **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
    """

    @given(error_msg=_error_messages)
    @settings(max_examples=100)
    def test_cross_account_error_fail_fast(self, error_msg: str) -> None:
        """CrossAccountError path: exit code != 0, stderr has error + allow-partial hint."""
        # Feature: early-cross-account-validation, Property 1
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session)
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patches[3], patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11], patches[12],
            patches[13],
            patch(
                "secrets_audit.cli.create_cross_account_session",
                side_effect=CrossAccountError(error_msg),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                ],
            )

        assert result.exit_code != 0, f"Expected non-zero exit, got {result.exit_code}"
        # Normalize \r\n to \n for comparison — Click may strip \r in output
        normalized_msg = error_msg.replace("\r\n", "\n").replace("\r", "\n").strip()
        normalized_stderr = result.stderr.replace("\r\n", "\n").replace("\r", "\n")
        assert normalized_msg in normalized_stderr, (
            f"Expected error message {error_msg!r} in stderr:\n{result.stderr}"
        )
        assert "Use --allow-partial" in result.stderr

    @given(error_msg=_error_messages)
    @settings(max_examples=100)
    def test_profile_session_error_fail_fast(self, error_msg: str) -> None:
        """ProfileSessionError path: exit code != 0, stderr has error + allow-partial hint."""
        # Feature: early-cross-account-validation, Property 1
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session)
        with (
            patches[0], patches[1], patches[2], patches[3],
            patch("secrets_audit.cli.validate_profile_name", return_value="bad-profile"),
            patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11], patches[12],
            patches[13],
            patch(
                "secrets_audit.cli.create_profile_session",
                side_effect=ProfileSessionError(error_msg),
            ),
        ):
            result = runner.invoke(
                main,
                ["--secret", _SECRET_NAME, "--master-profile", "bad-profile"],
            )

        assert result.exit_code != 0, f"Expected non-zero exit, got {result.exit_code}"
        # Normalize \r\n to \n for comparison — Click may strip \r in output
        normalized_msg = error_msg.replace("\r\n", "\n").replace("\r", "\n").strip()
        normalized_stderr = result.stderr.replace("\r\n", "\n").replace("\r", "\n")
        assert normalized_msg in normalized_stderr, (
            f"Expected error message {error_msg!r} in stderr:\n{result.stderr}"
        )
        assert "Use --allow-partial" in result.stderr


# ---------------------------------------------------------------------------
# Property 2: Fail-fast prevents expensive pipeline steps
# Feature: early-cross-account-validation, Property 2
# ---------------------------------------------------------------------------


class TestProperty2FailFastPreventsExpensiveSteps:
    """Property 2: Fail-fast prevents expensive pipeline steps.

    **Validates: Requirements 2.5**
    """

    @given(error_msg=_error_messages)
    @settings(max_examples=100)
    def test_simulate_not_called_on_fail_fast(self, error_msg: str) -> None:
        """simulate_principal_access is NOT called when early validation fails without --allow-partial."""
        # Feature: early-cross-account-validation, Property 2
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        mock_simulate = MagicMock(return_value=SimulationResult(principals=[]))

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", mock_simulate),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                side_effect=CrossAccountError(error_msg),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                ],
            )

        assert result.exit_code != 0
        mock_simulate.assert_not_called()


# ---------------------------------------------------------------------------
# Property 3: Allow-partial continues with warning
# Feature: early-cross-account-validation, Property 3
# ---------------------------------------------------------------------------


class TestProperty3AllowPartialContinuesWithWarning:
    """Property 3: Allow-partial continues with warning.

    **Validates: Requirements 3.2, 3.3, 3.4**
    """

    @given(error_msg=_error_messages)
    @settings(max_examples=100)
    def test_allow_partial_cross_account_continues_with_warning(self, error_msg: str) -> None:
        """--allow-partial with CrossAccountError: exit 0, warnings list non-empty."""
        # Feature: early-cross-account-validation, Property 3
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                side_effect=CrossAccountError(error_msg),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                    "--allow-partial",
                    "--output", "json",
                ],
            )

        assert result.exit_code == 0, f"Expected exit 0, got {result.exit_code}\nstderr: {result.stderr}"
        parsed = json.loads(result.output)
        assert len(parsed["warnings"]) >= 1, "Expected at least one warning"

    @given(error_msg=_error_messages)
    @settings(max_examples=100)
    def test_allow_partial_profile_continues_with_warning(self, error_msg: str) -> None:
        """--allow-partial with ProfileSessionError: exit 0, warnings list non-empty."""
        # Feature: early-cross-account-validation, Property 3
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value="bad-profile"),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_profile_session",
                side_effect=ProfileSessionError(error_msg),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-profile", "bad-profile",
                    "--allow-partial",
                    "--output", "json",
                ],
            )

        assert result.exit_code == 0, f"Expected exit 0, got {result.exit_code}\nstderr: {result.stderr}"
        parsed = json.loads(result.output)
        assert len(parsed["warnings"]) >= 1, "Expected at least one warning"


# ---------------------------------------------------------------------------
# Property 4: Allow-partial produces partial IC resolution
# Feature: early-cross-account-validation, Property 4
# ---------------------------------------------------------------------------

# Strategy for valid permission set names (alphanumeric, 1-20 chars, starts with letter)
_valid_ps_names = st.from_regex(r"[a-zA-Z][a-zA-Z0-9]{0,14}", fullmatch=True)


class TestProperty4AllowPartialProducesPartialIC:
    """Property 4: Allow-partial produces partial IC resolution.

    **Validates: Requirements 3.5**
    """

    @given(ps_name=_valid_ps_names)
    @settings(max_examples=100)
    def test_allow_partial_ic_principal_has_partial_flag(self, ps_name: str) -> None:
        """IC principal has ic_partial=True and permission_set_name matches when allow-partial fails."""
        # Feature: early-cross-account-validation, Property 4
        ic_principal = _build_ic_principal(ps_name)
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[ic_principal])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                side_effect=CrossAccountError("Access denied"),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                    "--allow-partial",
                    "--output", "json",
                ],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}\nstderr: {result.stderr}"
        parsed = json.loads(result.output)

        ic_principals = [p for p in parsed["principals"] if p.get("ic_partial") is True]
        assert len(ic_principals) == 1, f"Expected 1 IC partial principal, got {len(ic_principals)}"
        assert ic_principals[0]["permission_set_name"] == ps_name


# ---------------------------------------------------------------------------
# Property 5: Session reuse — single creation, same object
# Feature: early-cross-account-validation, Property 5
# ---------------------------------------------------------------------------


class TestProperty5SessionReuse:
    """Property 5: Session reuse — single creation, same object.

    **Validates: Requirements 1.3, 5.1**
    """

    @given(ps_name=_valid_ps_names)
    @settings(max_examples=100)
    def test_session_created_once_and_reused(self, ps_name: str) -> None:
        """Session creation called once; resolve_identity_center receives the same session object."""
        # Feature: early-cross-account-validation, Property 5
        ic_principal = _build_ic_principal(ps_name)
        session = _mock_session()
        mock_cross_session = MagicMock()
        mock_cross_session.region_name = "us-east-1"

        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[ic_principal])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                return_value=mock_cross_session,
            ) as mock_create,
            patch("secrets_audit.cli.resolve_identity_center") as mock_resolve_ic,
        ):
            mock_resolve_ic.return_value = IdentityCenterResolution(
                permission_set_name=ps_name,
            )
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                ],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}\nstderr: {result.stderr}"
        mock_create.assert_called_once()
        mock_resolve_ic.assert_called_once()
        # The first positional arg to resolve_identity_center should be the same session object
        assert mock_resolve_ic.call_args[0][0] is mock_cross_session


# ---------------------------------------------------------------------------
# Property 6: No session retry on allow-partial failure
# Feature: early-cross-account-validation, Property 6
# ---------------------------------------------------------------------------


class TestProperty6NoSessionRetryOnAllowPartial:
    """Property 6: No session retry on allow-partial failure.

    **Validates: Requirements 5.2**
    """

    @given(error_msg=_error_messages)
    @settings(max_examples=100)
    def test_session_creation_called_once_on_allow_partial_failure(self, error_msg: str) -> None:
        """Session creation called exactly once (early attempt), not retried in Step 7."""
        # Feature: early-cross-account-validation, Property 6
        ic_principal = _build_ic_principal("AdminAccess")
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[ic_principal])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                side_effect=CrossAccountError(error_msg),
            ) as mock_create,
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                    "--allow-partial",
                ],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}\nstderr: {result.stderr}"
        mock_create.assert_called_once()


# ---------------------------------------------------------------------------
# Property 7: Progress message emitted for early validation
# Feature: early-cross-account-validation, Property 7
# ---------------------------------------------------------------------------


class TestProperty7ProgressMessageEmitted:
    """Property 7: Progress message emitted for early validation.

    **Validates: Requirements 4.1**
    """

    @given(error_msg=_error_messages)
    @settings(max_examples=100)
    def test_progress_message_on_cross_account(self, error_msg: str) -> None:
        """stderr contains 'Validating cross-account access...' when not --quiet."""
        # Feature: early-cross-account-validation, Property 7
        session = _mock_session()
        mock_cross_session = MagicMock()
        mock_cross_session.region_name = "us-east-1"
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                return_value=mock_cross_session,
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                ],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}\nstderr: {result.stderr}"
        assert "Validating cross-account access..." in result.stderr


# ---------------------------------------------------------------------------
# Property 8: Quiet flag suppresses early validation progress
# Feature: early-cross-account-validation, Property 8
# ---------------------------------------------------------------------------


class TestProperty8QuietSuppressesProgress:
    """Property 8: Quiet flag suppresses early validation progress.

    **Validates: Requirements 4.2**
    """

    @given(error_msg=_error_messages)
    @settings(max_examples=100)
    def test_quiet_suppresses_validation_progress(self, error_msg: str) -> None:
        """stderr does NOT contain 'Validating cross-account access...' when --quiet is set."""
        # Feature: early-cross-account-validation, Property 8
        session = _mock_session()
        mock_cross_session = MagicMock()
        mock_cross_session.region_name = "us-east-1"
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                return_value=mock_cross_session,
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                    "--quiet",
                ],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}\nstderr: {result.stderr}"
        assert "Validating cross-account access..." not in result.stderr


# ===========================================================================
# Unit Tests (Tasks 5.1, 5.2, 5.3)
# ===========================================================================


# ---------------------------------------------------------------------------
# Task 5.1: Unit tests for --allow-partial flag
# ---------------------------------------------------------------------------


class TestAllowPartialFlagParsing:
    """Unit tests for --allow-partial flag parsing and help text.

    **Validates: Requirements 3.1, 3.6, 6.1, 6.2**
    """

    def test_allow_partial_in_help_output(self) -> None:
        """--allow-partial appears in --help output."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--allow-partial" in result.output

    def test_allow_partial_defaults_to_false(self) -> None:
        """--allow-partial defaults to False — cross-account failure causes exit != 0."""
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                side_effect=CrossAccountError("Access denied"),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                ],
            )

        # Without --allow-partial, fail-fast should trigger
        assert result.exit_code != 0

    def test_allow_partial_without_cross_account_flags_produces_normal_report(self) -> None:
        """--allow-partial without cross-account flags produces a normal report with no warnings."""
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
        ):
            result = runner.invoke(
                main,
                ["--secret", _SECRET_NAME, "--allow-partial", "--output", "json"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        parsed = json.loads(result.output)
        assert parsed["warnings"] == []


# ---------------------------------------------------------------------------
# Task 5.2: Unit tests for call ordering
# ---------------------------------------------------------------------------


class TestCallOrdering:
    """Unit tests for call ordering — early validation before expensive steps.

    **Validates: Requirements 1.1, 1.2**
    """

    def test_create_cross_account_session_called_before_simulate(self) -> None:
        """create_cross_account_session is called BEFORE simulate_principal_access."""
        session = _mock_session()
        mock_cross_session = MagicMock()
        mock_cross_session.region_name = "us-east-1"
        runner = CliRunner(mix_stderr=False)

        call_order: list[str] = []

        def track_create(*args, **kwargs):
            call_order.append("create_cross_account_session")
            return mock_cross_session

        def track_simulate(*args, **kwargs):
            call_order.append("simulate_principal_access")
            return SimulationResult(principals=[])

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", side_effect=track_simulate),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch("secrets_audit.cli.create_cross_account_session", side_effect=track_create),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                ],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}\nstderr: {result.stderr}"
        assert "create_cross_account_session" in call_order
        assert "simulate_principal_access" in call_order
        idx_create = call_order.index("create_cross_account_session")
        idx_simulate = call_order.index("simulate_principal_access")
        assert idx_create < idx_simulate, (
            f"create_cross_account_session (idx={idx_create}) should be called before "
            f"simulate_principal_access (idx={idx_simulate}). Order: {call_order}"
        )

    def test_create_profile_session_called_before_simulate(self) -> None:
        """create_profile_session is called BEFORE simulate_principal_access."""
        session = _mock_session()
        mock_profile_session = MagicMock()
        mock_profile_session.region_name = "us-east-1"
        runner = CliRunner(mix_stderr=False)

        call_order: list[str] = []

        def track_create_profile(*args, **kwargs):
            call_order.append("create_profile_session")
            return mock_profile_session

        def track_simulate(*args, **kwargs):
            call_order.append("simulate_principal_access")
            return SimulationResult(principals=[])

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value="mgmt-profile"),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", side_effect=track_simulate),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch("secrets_audit.cli.create_profile_session", side_effect=track_create_profile),
        ):
            result = runner.invoke(
                main,
                ["--secret", _SECRET_NAME, "--master-profile", "mgmt-profile"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}\nstderr: {result.stderr}"
        assert "create_profile_session" in call_order
        assert "simulate_principal_access" in call_order
        idx_create = call_order.index("create_profile_session")
        idx_simulate = call_order.index("simulate_principal_access")
        assert idx_create < idx_simulate, (
            f"create_profile_session (idx={idx_create}) should be called before "
            f"simulate_principal_access (idx={idx_simulate}). Order: {call_order}"
        )


# ---------------------------------------------------------------------------
# Task 5.3: Unit tests for fail-fast error message format
# ---------------------------------------------------------------------------


class TestFailFastErrorMessageFormat:
    """Unit tests for fail-fast error message format.

    **Validates: Requirements 2.3, 2.4**
    """

    def test_cross_account_error_writes_to_stderr_not_stdout(self) -> None:
        """Fail-fast error on CrossAccountError writes to stderr, not stdout."""
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                side_effect=CrossAccountError("Role assumption failed"),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                ],
            )

        assert result.exit_code != 0
        # Error should be on stderr
        assert "Role assumption failed" in result.stderr
        # stdout should NOT contain the error
        assert "Role assumption failed" not in result.output

    def test_profile_session_error_writes_to_stderr_not_stdout(self) -> None:
        """Fail-fast error on ProfileSessionError writes to stderr, not stdout."""
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value="bad-profile"),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_profile_session",
                side_effect=ProfileSessionError("Profile credentials expired"),
            ),
        ):
            result = runner.invoke(
                main,
                ["--secret", _SECRET_NAME, "--master-profile", "bad-profile"],
            )

        assert result.exit_code != 0
        # Error should be on stderr
        assert "Profile credentials expired" in result.stderr
        # stdout should NOT contain the error
        assert "Profile credentials expired" not in result.output

    def test_error_message_includes_allow_partial_hint(self) -> None:
        """Error message includes 'Use --allow-partial to continue with a partial report'."""
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=_SECRET_NAME),
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name=_SECRET_NAME, arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                side_effect=CrossAccountError("Access denied"),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                ],
            )

        assert result.exit_code != 0
        assert "Use --allow-partial to continue with a partial report" in result.stderr
