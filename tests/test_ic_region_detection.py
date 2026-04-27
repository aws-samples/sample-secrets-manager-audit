"""Property-based and unit tests for the ic-region-detection feature.

Tests cover:
- Property 1: Default region tried first, no duplicates
- Property 2: Fallback detection returns correct region
- Property 3: All-empty raises NoICInstanceError
- Property 4: API errors in fallback don't halt detection
- Property 5: Explicit ic_region tries only that region
- Property 6: Region propagation to all IC clients
- Unit tests for resolve_identity_center() ic_region threading
- Unit tests for CLI --ic-region wiring
- Unit tests for graceful failure scenarios
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, call, patch

import botocore.exceptions
import pytest
from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.cli import main
from secrets_audit.identity_center import (
    FALLBACK_REGIONS,
    NoICInstanceError,
    find_ic_instance,
    find_permission_set_arn,
    get_account_assignments,
    resolve_group,
    resolve_identity_center,
    resolve_user,
    _list_group_members,
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


def _make_client_error(code: str = "AccessDeniedException", message: str = "Access Denied"):
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": message}},
        "ListInstances",
    )



# ===========================================================================
# Property 1: Default region tried first, no duplicates
# Feature: ic-region-detection, Property 1
# ===========================================================================


class TestProperty1DefaultRegionFirstNoDuplicates:
    """Property 1: Default region tried first, no duplicates.

    **Validates: Requirements 1.1, 1.3**
    """

    @given(default_region=st.sampled_from(FALLBACK_REGIONS))
    @settings(max_examples=100)
    def test_default_region_tried_first_no_duplicates(self, default_region: str) -> None:
        # Feature: ic-region-detection, Property 1
        session = _mock_session(region=default_region)
        clients_created: list[dict] = []

        def mock_client_factory(service, **kwargs):
            mock_client = MagicMock()
            mock_client.list_instances.return_value = {"Instances": []}
            clients_created.append({"service": service, "kwargs": kwargs})
            return mock_client

        session.client.side_effect = mock_client_factory

        with pytest.raises(NoICInstanceError):
            find_ic_instance(session, ic_region=None)

        sso_calls = [c for c in clients_created if c["service"] == "sso-admin"]
        assert len(sso_calls) >= 1
        # First call uses session default (no explicit region_name)
        assert "region_name" not in sso_calls[0]["kwargs"]
        subsequent_regions = [c["kwargs"]["region_name"] for c in sso_calls[1:]]
        all_regions = [default_region] + subsequent_regions
        assert len(all_regions) == len(set(all_regions))
        assert default_region not in subsequent_regions


# ===========================================================================
# Property 2: Fallback detection returns correct region
# Feature: ic-region-detection, Property 2
# ===========================================================================


class TestProperty2FallbackReturnsCorrectRegion:
    """Property 2: Fallback detection returns correct region.

    **Validates: Requirements 1.2, 1.4**
    """

    @given(target_region=st.sampled_from(FALLBACK_REGIONS))
    @settings(max_examples=100)
    def test_fallback_detection_returns_correct_region(self, target_region: str) -> None:
        # Feature: ic-region-detection, Property 2
        default_region = "ap-northeast-1"
        session = _mock_session(region=default_region)

        def mock_client_factory(service, **kwargs):
            mock_client = MagicMock()
            region = kwargs.get("region_name", default_region)
            if region == target_region:
                mock_client.list_instances.return_value = {
                    "Instances": [{"InstanceArn": _INSTANCE_ARN,
                                   "IdentityStoreId": _IDENTITY_STORE_ID}]
                }
            else:
                mock_client.list_instances.return_value = {"Instances": []}
            return mock_client

        session.client.side_effect = mock_client_factory
        arn, store_id, detected_region = find_ic_instance(session, ic_region=None)
        assert arn == _INSTANCE_ARN
        assert store_id == _IDENTITY_STORE_ID
        assert detected_region == target_region


# ===========================================================================
# Property 3: All-empty raises NoICInstanceError
# Feature: ic-region-detection, Property 3
# ===========================================================================


class TestProperty3AllEmptyRaises:
    """Property 3: All-empty raises NoICInstanceError.

    **Validates: Requirements 1.5**
    """

    @given(default_region=st.sampled_from(FALLBACK_REGIONS))
    @settings(max_examples=100)
    def test_all_empty_raises_no_ic_instance_error(self, default_region: str) -> None:
        # Feature: ic-region-detection, Property 3
        session = _mock_session(region=default_region)

        def mock_client_factory(service, **kwargs):
            mock_client = MagicMock()
            mock_client.list_instances.return_value = {"Instances": []}
            return mock_client

        session.client.side_effect = mock_client_factory
        with pytest.raises(NoICInstanceError):
            find_ic_instance(session, ic_region=None)


# ===========================================================================
# Property 4: API errors in fallback don't halt detection
# Feature: ic-region-detection, Property 4
# ===========================================================================


class TestProperty4APIErrorsDontHalt:
    """Property 4: API errors in fallback regions do not halt detection.

    **Validates: Requirements 1.6, 5.4**
    """

    @given(data=st.data())
    @settings(max_examples=100)
    def test_api_errors_dont_halt_detection(self, data: st.DataObject) -> None:
        # Feature: ic-region-detection, Property 4
        error_region = data.draw(st.sampled_from(FALLBACK_REGIONS))
        success_region = data.draw(
            st.sampled_from([r for r in FALLBACK_REGIONS if r != error_region])
        )
        default_region = "ap-northeast-1"
        session = _mock_session(region=default_region)

        def mock_client_factory(service, **kwargs):
            mock_client = MagicMock()
            region = kwargs.get("region_name", default_region)
            if region == error_region:
                mock_client.list_instances.side_effect = _make_client_error()
            elif region == success_region:
                mock_client.list_instances.return_value = {
                    "Instances": [{"InstanceArn": _INSTANCE_ARN,
                                   "IdentityStoreId": _IDENTITY_STORE_ID}]
                }
            else:
                mock_client.list_instances.return_value = {"Instances": []}
            return mock_client

        session.client.side_effect = mock_client_factory
        arn, store_id, detected = find_ic_instance(session, ic_region=None)
        assert arn == _INSTANCE_ARN
        assert detected == success_region


# ===========================================================================
# Property 5: Explicit ic_region tries only that region
# Feature: ic-region-detection, Property 5
# ===========================================================================

_valid_regions = st.sampled_from(
    ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
     "ap-southeast-1", "ap-northeast-1"]
)


class TestProperty5ExplicitRegionSingleCall:
    """Property 5: Explicit ic_region tries only that region.

    **Validates: Requirements 2.3, 2.4**
    """

    @given(region=_valid_regions)
    @settings(max_examples=100)
    def test_explicit_region_returns_instance(self, region: str) -> None:
        # Feature: ic-region-detection, Property 5
        session = _mock_session(region="us-east-1")
        clients_created: list[dict] = []

        def mock_client_factory(service, **kwargs):
            mock_client = MagicMock()
            mock_client.list_instances.return_value = {
                "Instances": [{"InstanceArn": _INSTANCE_ARN,
                               "IdentityStoreId": _IDENTITY_STORE_ID}]
            }
            clients_created.append({"service": service, "kwargs": kwargs})
            return mock_client

        session.client.side_effect = mock_client_factory
        arn, store_id, detected = find_ic_instance(session, ic_region=region)
        assert arn == _INSTANCE_ARN and detected == region
        sso = [c for c in clients_created if c["service"] == "sso-admin"]
        assert len(sso) == 1
        assert sso[0]["kwargs"].get("region_name") == region

    @given(region=_valid_regions)
    @settings(max_examples=100)
    def test_explicit_region_empty_raises_no_fallback(self, region: str) -> None:
        # Feature: ic-region-detection, Property 5
        session = _mock_session(region="us-east-1")
        clients_created: list[dict] = []

        def mock_client_factory(service, **kwargs):
            mock_client = MagicMock()
            mock_client.list_instances.return_value = {"Instances": []}
            clients_created.append({"service": service, "kwargs": kwargs})
            return mock_client

        session.client.side_effect = mock_client_factory
        with pytest.raises(NoICInstanceError):
            find_ic_instance(session, ic_region=region)
        sso = [c for c in clients_created if c["service"] == "sso-admin"]
        assert len(sso) == 1


# ===========================================================================
# Property 6: Region propagation to all IC clients
# Feature: ic-region-detection, Property 6
# ===========================================================================

_nonNone_regions = st.sampled_from(
    ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"]
)


class TestProperty6RegionPropagation:
    """Property 6: Region propagation to all IC clients.

    **Validates: Requirements 3.1, 3.2, 3.3**
    """

    @given(ic_region=_nonNone_regions)
    @settings(max_examples=100)
    def test_find_permission_set_arn_propagates_region(self, ic_region: str) -> None:
        # Feature: ic-region-detection, Property 6
        session = _mock_session()
        mock_client = MagicMock()
        mock_client.list_permission_sets.return_value = {"PermissionSets": []}
        session.client.return_value = mock_client
        find_permission_set_arn(session, _INSTANCE_ARN, "TestPS", ic_region=ic_region)
        session.client.assert_called_once()
        _, kwargs = session.client.call_args
        assert kwargs.get("region_name") == ic_region

    @given(ic_region=_nonNone_regions)
    @settings(max_examples=100)
    def test_get_account_assignments_propagates_region(self, ic_region: str) -> None:
        # Feature: ic-region-detection, Property 6
        session = _mock_session()
        mock_client = MagicMock()
        mock_client.list_account_assignments.return_value = {"AccountAssignments": []}
        session.client.return_value = mock_client
        get_account_assignments(
            session, _INSTANCE_ARN, "ps-arn", "123456789012", ic_region=ic_region
        )
        session.client.assert_called_once()
        _, kwargs = session.client.call_args
        assert kwargs.get("region_name") == ic_region


    @given(ic_region=_nonNone_regions)
    @settings(max_examples=100)
    def test_resolve_user_propagates_region(self, ic_region: str) -> None:
        # Feature: ic-region-detection, Property 6
        session = _mock_session()
        mock_client = MagicMock()
        mock_client.describe_user.return_value = {
            "DisplayName": "Test User", "Emails": []
        }
        session.client.return_value = mock_client
        resolve_user(session, _IDENTITY_STORE_ID, "user-123", ic_region=ic_region)
        session.client.assert_called_once()
        _, kwargs = session.client.call_args
        assert kwargs.get("region_name") == ic_region

    @given(ic_region=_nonNone_regions)
    @settings(max_examples=100)
    def test_resolve_group_propagates_region(self, ic_region: str) -> None:
        # Feature: ic-region-detection, Property 6
        session = _mock_session()
        mock_client = MagicMock()
        mock_client.describe_group.return_value = {"DisplayName": "TestGroup"}
        session.client.return_value = mock_client
        resolve_group(session, _IDENTITY_STORE_ID, "group-123", ic_region=ic_region)
        session.client.assert_called_once()
        _, kwargs = session.client.call_args
        assert kwargs.get("region_name") == ic_region

    @given(ic_region=_nonNone_regions)
    @settings(max_examples=100)
    def test_list_group_members_propagates_region(self, ic_region: str) -> None:
        # Feature: ic-region-detection, Property 6
        session = _mock_session()
        mock_client = MagicMock()
        mock_client.list_group_memberships.return_value = {"GroupMemberships": []}
        session.client.return_value = mock_client
        _list_group_members(session, _IDENTITY_STORE_ID, "g-1", ic_region=ic_region)
        session.client.assert_called_once()
        _, kwargs = session.client.call_args
        assert kwargs.get("region_name") == ic_region


# ===========================================================================
# Task 4.2: Unit tests for resolve_identity_center() ic_region threading
# ===========================================================================


class TestResolveIdentityCenterRegionThreading:
    """Unit tests for resolve_identity_center() ic_region threading."""

    def test_detected_region_passed_to_downstream(self) -> None:
        """detected_region from find_ic_instance is threaded to downstream."""
        session = _mock_session()
        detected = "eu-west-1"
        with (
            patch(
                "secrets_audit.identity_center.find_ic_instance",
                return_value=(_INSTANCE_ARN, _IDENTITY_STORE_ID, detected),
            ),
            patch(
                "secrets_audit.identity_center.find_permission_set_arn",
                return_value="ps-arn-123",
            ) as mock_fps,
            patch(
                "secrets_audit.identity_center.get_account_assignments",
                return_value=[],
            ) as mock_gaa,
        ):
            result = resolve_identity_center(
                session, "AdminAccess", "123456789012", ic_region=None
            )
        mock_fps.assert_called_once()
        assert mock_fps.call_args.kwargs.get("ic_region") == detected
        mock_gaa.assert_called_once()
        assert mock_gaa.call_args.kwargs.get("ic_region") == detected
        assert result.partial is False


    def test_explicit_ic_region_overrides_detected(self) -> None:
        """Explicit ic_region is used instead of detected_region."""
        session = _mock_session()
        explicit = "ap-southeast-1"
        with (
            patch(
                "secrets_audit.identity_center.find_ic_instance",
                return_value=(_INSTANCE_ARN, _IDENTITY_STORE_ID, explicit),
            ),
            patch(
                "secrets_audit.identity_center.find_permission_set_arn",
                return_value="ps-arn-123",
            ) as mock_fps,
            patch(
                "secrets_audit.identity_center.get_account_assignments",
                return_value=[],
            ) as mock_gaa,
        ):
            result = resolve_identity_center(
                session, "AdminAccess", "123456789012", ic_region=explicit
            )
        assert mock_fps.call_args.kwargs.get("ic_region") == explicit
        assert mock_gaa.call_args.kwargs.get("ic_region") == explicit

    def test_no_ic_instance_error_produces_partial(self) -> None:
        """NoICInstanceError produces partial result with warning."""
        session = _mock_session()
        with patch(
            "secrets_audit.identity_center.find_ic_instance",
            side_effect=NoICInstanceError("No IC instance found"),
        ):
            result = resolve_identity_center(
                session, "AdminAccess", "123456789012", ic_region=None
            )
        assert result.partial is True
        assert len(result.warnings) >= 1
        assert "Identity Center" in result.warnings[0]


# ===========================================================================
# Task 6.3: Unit tests for CLI --ic-region wiring
# ===========================================================================


class TestCLIIcRegionWiring:
    """Unit tests for CLI --ic-region wiring."""

    def test_help_contains_ic_region(self) -> None:
        """--help contains --ic-region with auto-detection description."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--ic-region" in result.output
        assert "auto-detect" in result.output.lower()
        assert "cross-account" in result.output.lower()

    def test_ic_region_passes_through_validate_region(self) -> None:
        """--ic-region value passes through validate_region()."""
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)
        patches = _pipeline_patches(session)
        with (
            patches[0], patches[1], patches[2],
            patch("secrets_audit.cli.validate_region", side_effect=lambda v: v) as vr,
            patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
        ):
            result = runner.invoke(
                main, ["--secret", _SECRET_NAME, "--ic-region", "us-west-2"]
            )
        calls = [c.args[0] for c in vr.call_args_list]
        assert "us-west-2" in calls


    def test_ic_region_without_cross_account_exits_zero(self) -> None:
        """--ic-region without cross-account flags exits 0."""
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
                ["--secret", _SECRET_NAME, "--ic-region", "us-west-2"],
            )
        assert result.exit_code == 0

    def test_detecting_progress_message_when_no_ic_region(self) -> None:
        """'Detecting IC region...' in stderr when not --quiet and IC roles exist."""
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        ic_principal = _build_ic_principal("AdminAccess")
        runner = CliRunner(mix_stderr=False)
        patches = _pipeline_patches(session, principals=[ic_principal])
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patches[3], patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
            patch("secrets_audit.cli.create_cross_account_session",
                  return_value=cross_session),
            patch("secrets_audit.cli.resolve_identity_center",
                  return_value=IdentityCenterResolution(
                      permission_set_name="AdminAccess")),
        ):
            result = runner.invoke(main, [
                "--secret", _SECRET_NAME,
                "--master-account-id", _ACCOUNT_ID,
                "--cross-account-role-arn", _ROLE_ARN,
            ])
        assert result.exit_code == 0
        assert "Detecting Identity Center region..." in result.stderr


    def test_quiet_suppresses_detection_progress(self) -> None:
        """--quiet suppresses the detection progress message."""
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        ic_principal = _build_ic_principal("AdminAccess")
        runner = CliRunner(mix_stderr=False)
        patches = _pipeline_patches(session, principals=[ic_principal])
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patches[3], patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
            patch("secrets_audit.cli.create_cross_account_session",
                  return_value=cross_session),
            patch("secrets_audit.cli.resolve_identity_center",
                  return_value=IdentityCenterResolution(
                      permission_set_name="AdminAccess")),
        ):
            result = runner.invoke(main, [
                "--secret", _SECRET_NAME,
                "--master-account-id", _ACCOUNT_ID,
                "--cross-account-role-arn", _ROLE_ARN,
                "--quiet",
            ])
        assert result.exit_code == 0
        assert "Detecting Identity Center region..." not in result.stderr


    def test_ic_region_passed_to_resolve_identity_center(self) -> None:
        """--ic-region with cross-account passes value to resolve_identity_center."""
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        ic_principal = _build_ic_principal("AdminAccess")
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
            patch("secrets_audit.cli.create_cross_account_session",
                  return_value=cross_session),
            patch("secrets_audit.cli.resolve_identity_center",
                  return_value=IdentityCenterResolution(
                      permission_set_name="AdminAccess")) as mock_ric,
        ):
            result = runner.invoke(main, [
                "--secret", _SECRET_NAME,
                "--master-account-id", _ACCOUNT_ID,
                "--cross-account-role-arn", _ROLE_ARN,
                "--ic-region", "eu-west-1",
            ])
        assert result.exit_code == 0
        mock_ric.assert_called_once()
        assert mock_ric.call_args.kwargs.get("ic_region") == "eu-west-1"


# ===========================================================================
# Task 7.1: Unit tests for graceful failure scenarios
# ===========================================================================


class TestGracefulFailureScenarios:
    """Unit tests for graceful failure scenarios."""

    def test_auto_detection_failure_produces_partial_ic(self) -> None:
        """Auto-detection failure: IC principals get ic_partial=True with warning."""
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        ic_principal = _build_ic_principal("AdminAccess")
        runner = CliRunner(mix_stderr=False)
        patches = _pipeline_patches(session, principals=[ic_principal])
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patches[3], patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
            patch("secrets_audit.cli.create_cross_account_session",
                  return_value=cross_session),
            patch("secrets_audit.cli.resolve_identity_center",
                  return_value=IdentityCenterResolution(
                      permission_set_name="AdminAccess",
                      partial=True,
                      warnings=["No Identity Center instance found"])),
        ):
            result = runner.invoke(main, [
                "--secret", _SECRET_NAME,
                "--master-account-id", _ACCOUNT_ID,
                "--cross-account-role-arn", _ROLE_ARN,
                "--output", "json",
            ])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        ic_ps = [p for p in parsed["principals"] if p.get("ic_partial") is True]
        assert len(ic_ps) == 1


    def test_auto_detection_failure_allow_partial_exit_zero(self) -> None:
        """Auto-detection failure with --allow-partial: warning, exit 0."""
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        ic_principal = _build_ic_principal("AdminAccess")
        runner = CliRunner(mix_stderr=False)
        patches = _pipeline_patches(session, principals=[ic_principal])
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patches[3], patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
            patch("secrets_audit.cli.create_cross_account_session",
                  return_value=cross_session),
            patch("secrets_audit.cli.resolve_identity_center",
                  return_value=IdentityCenterResolution(
                      permission_set_name="AdminAccess",
                      partial=True,
                      warnings=["No IC instance found in any region"])),
        ):
            result = runner.invoke(main, [
                "--secret", _SECRET_NAME,
                "--master-account-id", _ACCOUNT_ID,
                "--cross-account-role-arn", _ROLE_ARN,
                "--allow-partial",
                "--output", "json",
            ])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        ic_ps = [p for p in parsed["principals"] if p.get("ic_partial") is True]
        assert len(ic_ps) == 1


    def test_explicit_ic_region_empty_produces_partial(self) -> None:
        """Explicit --ic-region pointing to empty region: same partial behavior."""
        session = _mock_session()
        cross_session = MagicMock()
        cross_session.region_name = "us-east-1"
        ic_principal = _build_ic_principal("AdminAccess")
        runner = CliRunner(mix_stderr=False)
        patches = _pipeline_patches(session, principals=[ic_principal])
        with (
            patches[0],
            patch("secrets_audit.cli.validate_account_id", return_value=_ACCOUNT_ID),
            patch("secrets_audit.cli.validate_role_arn", return_value=_ROLE_ARN),
            patches[3], patches[4], patches[5], patches[6], patches[7],
            patches[8], patches[9], patches[10], patches[11],
            patches[12], patches[13],
            patch("secrets_audit.cli.create_cross_account_session",
                  return_value=cross_session),
            patch("secrets_audit.cli.resolve_identity_center",
                  return_value=IdentityCenterResolution(
                      permission_set_name="AdminAccess",
                      partial=True,
                      warnings=["No IC instance in region eu-central-1"])),
        ):
            result = runner.invoke(main, [
                "--secret", _SECRET_NAME,
                "--master-account-id", _ACCOUNT_ID,
                "--cross-account-role-arn", _ROLE_ARN,
                "--ic-region", "eu-central-1",
                "--output", "json",
            ])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        ic_ps = [p for p in parsed["principals"] if p.get("ic_partial") is True]
        assert len(ic_ps) == 1
