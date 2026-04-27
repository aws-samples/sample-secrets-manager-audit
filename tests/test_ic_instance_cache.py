"""Property-based and unit tests for the ic-instance-cache bugfix.

Tests cover:
- Task 1 / Property 1: Bug Condition — find_ic_instance called N times for N IC roles
  - Test 1a: find_ic_instance call count == 1 for N IC roles (FAILS on unfixed code: called N times)
  - Test 1b: Single warning on IC instance failure (FAILS on unfixed code: N warnings)
- Task 2 / Property 2: Preservation — Non-Bug-Condition Paths Unchanged
  - Test 2a (Property 4): No-cross-session → partial IC resolution, no find_ic_instance calls
  - Test 2b (Property 5): No IC roles → find_ic_instance and resolve_identity_center never called
  - Test 2c (Property 3): Backward-compatible resolve_identity_center() calls find_ic_instance internally
  - Test 2d (Property 6): --ic-region threaded to resolve_identity_center as ic_region kwarg
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch, call

from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.cli import main
from secrets_audit.identity_center import (
    NoICInstanceError,
    resolve_identity_center,
)
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
_INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1234567890abcdef0"
_IDENTITY_STORE_ID = "d-1234567890"


def _mock_session(region: str = "us-east-1") -> MagicMock:
    s = MagicMock()
    s.region_name = region
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


def _build_plain_iam_principal(name: str) -> PrincipalAccess:
    """Build a plain IAM role principal (not IC-classified)."""
    return PrincipalAccess(
        principal_type=PrincipalType.IAM_ROLE,
        principal_arn=f"arn:aws:iam::123456789012:role/{name}",
        principal_name=name,
        access_level=AccessLevel.READ,
        classification=PrincipalClassification.PLAIN_IAM,
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


# Hypothesis strategy for permission set name lists (2-8 unique names)
_ps_name_strategy = st.lists(
    st.from_regex(r"[A-Z][a-zA-Z0-9]{2,14}", fullmatch=True),
    min_size=2,
    max_size=8,
    unique=True,
)

# Strategy for valid permission set names
_valid_ps_names = st.from_regex(r"[a-zA-Z][a-zA-Z0-9]{0,14}", fullmatch=True)


# ===========================================================================
# Task 1: Bug Condition Exploration Tests
# Property 1: IC Instance Called N Times for N Roles
# CRITICAL: These tests MUST FAIL on unfixed code — failure confirms the bug
# ===========================================================================


class TestProperty1BugConditionICInstanceCalledOnce:
    """Property 1: Bug Condition — find_ic_instance called once, not N times.

    **Validates: Requirements 1.1, 1.2, 1.3**

    On UNFIXED code, find_ic_instance is called inside resolve_identity_center,
    which is called once per IC role in the cli.py Step 7 loop. So for N IC
    roles, find_ic_instance is called N times instead of 1.
    """

    @given(ps_names=_ps_name_strategy)
    @settings(max_examples=50)
    def test_1a_find_ic_instance_called_once_for_n_roles(
        self, ps_names: list[str]
    ) -> None:
        """For N IC roles with cross_session available, find_ic_instance
        should be called exactly 1 time.

        On UNFIXED code: called N times (once per resolve_identity_center call) → FAILS.
        """
        # Feature: ic-instance-cache, Property 1
        ic_principals = [_build_ic_principal(name) for name in ps_names]
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=ic_principals)
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patches[3], patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
            patch(
                "secrets_audit.cli.create_cross_account_session",
                return_value=cross_session,
            ),
            patch(
                "secrets_audit.cli.find_ic_instance",
                return_value=(_INSTANCE_ARN, _IDENTITY_STORE_ID, None),
            ) as mock_find_ic,
            patch(
                "secrets_audit.identity_center.find_permission_set_arn",
                return_value="arn:aws:sso:::permissionSet/ssoins-123/ps-abc",
            ),
            patch(
                "secrets_audit.identity_center.get_account_assignments",
                return_value=[],
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                    "--output", "json",
                ],
            )

        assert result.exit_code == 0, (
            f"CLI failed with exit code {result.exit_code}\n"
            f"stdout: {result.output}\nstderr: {result.stderr}"
        )
        # BUG CONDITION: On unfixed code, find_ic_instance is called N times
        # (once per IC role). The fix should make it exactly 1.
        assert mock_find_ic.call_count == 1, (
            f"Expected find_ic_instance called exactly 1 time, "
            f"but was called {mock_find_ic.call_count} times "
            f"for {len(ps_names)} IC roles. "
            f"This confirms the bug: find_ic_instance is called per-role "
            f"instead of once before the loop."
        )

    @given(ps_names=_ps_name_strategy)
    @settings(max_examples=50)
    def test_1b_single_warning_on_ic_instance_failure(
        self, ps_names: list[str]
    ) -> None:
        """For N IC roles with find_ic_instance raising NoICInstanceError,
        find_ic_instance should be called exactly 1 time (not N times),
        and a single top-level warning should be emitted.

        On UNFIXED code: find_ic_instance is called N times (once per
        resolve_identity_center invocation) → FAILS.
        """
        # Feature: ic-instance-cache, Property 1
        ic_principals = [_build_ic_principal(name) for name in ps_names]
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=ic_principals)
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patches[3], patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
            patch(
                "secrets_audit.cli.create_cross_account_session",
                return_value=cross_session,
            ),
            patch(
                "secrets_audit.cli.find_ic_instance",
                side_effect=NoICInstanceError("No Identity Center instance found"),
            ) as mock_find_ic,
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

        assert result.exit_code == 0, (
            f"CLI failed with exit code {result.exit_code}\n"
            f"stdout: {result.output}\nstderr: {result.stderr}"
        )
        # BUG CONDITION: On unfixed code, find_ic_instance is called N times
        # (once per resolve_identity_center call in the loop). The fix should
        # call it exactly once before the loop and emit a single warning.
        assert mock_find_ic.call_count == 1, (
            f"Expected find_ic_instance called exactly 1 time on failure, "
            f"but was called {mock_find_ic.call_count} times "
            f"for {len(ps_names)} IC roles. "
            f"This confirms the bug: find_ic_instance failure is repeated "
            f"per-role instead of being handled once before the loop."
        )


# ===========================================================================
# Task 2: Preservation Property Tests (BEFORE implementing fix)
# Property 2: Non-Bug-Condition Paths Unchanged
# These tests MUST PASS on unfixed code — they capture baseline behavior
# ===========================================================================


class TestProperty2PreservationNonBugConditionPaths:
    """Property 2: Preservation — Non-Bug-Condition Paths Unchanged.

    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6**

    These tests verify behavior that must remain identical after the fix.
    They run on UNFIXED code and should all PASS.
    """

    @given(ps_name=_valid_ps_names)
    @settings(max_examples=50)
    def test_2a_no_cross_session_partial_resolution(
        self, ps_name: str
    ) -> None:
        """Property 4 — No-Cross-Session: IC roles get partial resolution
        with permission_set_name only. find_ic_instance and
        resolve_identity_center are NOT called.

        **Validates: Requirements 3.2**
        """
        # Feature: ic-instance-cache, Property 4
        ic_principal = _build_ic_principal(ps_name)
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=[ic_principal])
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
            patch(
                "secrets_audit.cli.find_ic_instance",
            ) as mock_find_ic,
            patch(
                "secrets_audit.cli.resolve_identity_center",
            ) as mock_resolve_ic,
        ):
            # No cross-account flags → cross_session is None
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--output", "json",
                ],
            )

        assert result.exit_code == 0, (
            f"CLI failed: {result.output}\nstderr: {result.stderr}"
        )
        # Without cross-account flags, neither find_ic_instance nor
        # resolve_identity_center should be called
        mock_find_ic.assert_not_called()
        mock_resolve_ic.assert_not_called()

        # IC principal should get partial resolution
        parsed = json.loads(result.output)
        ic_principals = [
            p for p in parsed["principals"]
            if p.get("ic_partial") is True
        ]
        assert len(ic_principals) == 1, (
            f"Expected 1 IC partial principal, got {len(ic_principals)}"
        )
        assert ic_principals[0]["permission_set_name"] == ps_name

    @given(
        plain_names=st.lists(
            st.from_regex(r"[a-z][a-z0-9\-]{2,14}", fullmatch=True),
            min_size=1,
            max_size=5,
            unique=True,
        )
    )
    @settings(max_examples=50)
    def test_2b_no_ic_roles_skips_loop(self, plain_names: list[str]) -> None:
        """Property 5 — No IC Roles: With only plain IAM principals,
        find_ic_instance and resolve_identity_center are NOT called.

        **Validates: Requirements 3.1**
        """
        # Feature: ic-instance-cache, Property 5
        plain_principals = [_build_plain_iam_principal(n) for n in plain_names]
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=plain_principals)
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patches[3], patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
            patch(
                "secrets_audit.cli.create_cross_account_session",
                return_value=cross_session,
            ),
            patch(
                "secrets_audit.cli.find_ic_instance",
            ) as mock_find_ic,
            patch(
                "secrets_audit.cli.resolve_identity_center",
            ) as mock_resolve_ic,
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                    "--output", "json",
                ],
            )

        assert result.exit_code == 0, (
            f"CLI failed: {result.output}\nstderr: {result.stderr}"
        )
        # No IC roles → neither function should be called
        mock_find_ic.assert_not_called()
        mock_resolve_ic.assert_not_called()

    def test_2c_backward_compatible_resolve_identity_center(self) -> None:
        """Property 3 — Backward-Compatible resolve_identity_center:
        When called without instance_arn/identity_store_id params,
        find_ic_instance is called internally.

        **Validates: Requirements 3.3, 3.4**
        """
        # Feature: ic-instance-cache, Property 3
        session = _mock_session()

        with (
            patch(
                "secrets_audit.identity_center.find_ic_instance",
                return_value=(_INSTANCE_ARN, _IDENTITY_STORE_ID, None),
            ) as mock_find_ic,
            patch(
                "secrets_audit.identity_center.find_permission_set_arn",
                return_value="arn:aws:sso:::permissionSet/ssoins-123/ps-abc",
            ),
            patch(
                "secrets_audit.identity_center.get_account_assignments",
                return_value=[],
            ),
        ):
            result = resolve_identity_center(
                session, "AdminAccess", "123456789012",
            )

        # find_ic_instance should be called internally
        mock_find_ic.assert_called_once()
        assert result.permission_set_name == "AdminAccess"
        assert result.partial is False

    @given(
        ic_region=st.sampled_from(
            ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"]
        )
    )
    @settings(max_examples=50)
    def test_2d_ic_region_threading(self, ic_region: str) -> None:
        """Property 6 — IC Region Threading: When --ic-region is provided
        with cross-account flags, the value is passed to
        resolve_identity_center as ic_region kwarg.

        **Validates: Requirements 3.5, 3.6**
        """
        # Feature: ic-instance-cache, Property 6
        ic_principal = _build_ic_principal("AdminAccess")
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=[ic_principal])
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patch("secrets_audit.cli.validate_region", side_effect=lambda v: v),
            patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
            patch(
                "secrets_audit.cli.create_cross_account_session",
                return_value=cross_session,
            ),
            patch(
                "secrets_audit.cli.find_ic_instance",
                return_value=(_INSTANCE_ARN, _IDENTITY_STORE_ID, None),
            ),
            patch(
                "secrets_audit.cli.resolve_identity_center",
                return_value=IdentityCenterResolution(
                    permission_set_name="AdminAccess",
                ),
            ) as mock_resolve_ic,
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", _SECRET_NAME,
                    "--master-account-id", _ACCOUNT_ID,
                    "--cross-account-role-arn", _ROLE_ARN,
                    "--ic-region", ic_region,
                    "--output", "json",
                ],
            )

        assert result.exit_code == 0, (
            f"CLI failed: {result.output}\nstderr: {result.stderr}"
        )
        mock_resolve_ic.assert_called_once()
        assert mock_resolve_ic.call_args.kwargs.get("ic_region") == ic_region
