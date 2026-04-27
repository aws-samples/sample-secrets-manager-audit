"""Property-based and unit tests for the credential-expiry-guard feature.

Feature: credential-expiry-guard
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest
from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.aws_clients import get_credential_expiry, is_expired_token_error
from secrets_audit.cli import main
from secrets_audit.cloudtrail import CREDENTIALS_EXPIRED
from secrets_audit.models import (
    AuditReport,
    PrincipalAccess,
    PrincipalType,
    AccessLevel,
    SecretMetadata,
)
from secrets_audit.pipeline import AuditParams, run_audit
from secrets_audit.resolver import SimulationResult, simulate_principal_access


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_EXPIRED_CODES = ["ExpiredTokenException", "ExpiredToken", "RequestExpired"]
_NON_EXPIRED_CODES = [
    "AccessDeniedException",
    "ThrottlingException",
    "NoSuchEntity",
    "ValidationException",
]

_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf"  # nosec B105


def _make_client_error(code: str, message: str = "test") -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": message}}, "TestOp"
    )


def _mock_session() -> MagicMock:
    s = MagicMock()
    s.region_name = "us-east-1"
    return s


def _pipeline_patches(mock_session, sim_result=None, last_accessed_side_effect=None):
    """Return a dict of common pipeline patches for run_audit tests."""
    if sim_result is None:
        sim_result = SimulationResult(principals=[])
    patches = {
        "secrets_audit.pipeline.create_prod_session": MagicMock(return_value=mock_session),
        "secrets_audit.pipeline.get_caller_identity": MagicMock(
            return_value="arn:aws:iam::123456789012:user/tester"
        ),
        "secrets_audit.pipeline.resolve_secret": MagicMock(
            return_value=SecretMetadata(name="test/secret", arn=_SECRET_ARN)
        ),
        "secrets_audit.pipeline.get_resource_policy_principals": MagicMock(return_value=[]),
        "secrets_audit.pipeline.list_iam_roles": MagicMock(return_value=[]),
        "secrets_audit.pipeline.list_iam_users": MagicMock(return_value=[]),
        "secrets_audit.pipeline.simulate_principal_access": MagicMock(return_value=sim_result),
        "secrets_audit.pipeline.classify_principal": MagicMock(side_effect=lambda _s, p: p),
    }
    if last_accessed_side_effect is not None:
        patches["secrets_audit.pipeline.get_last_accessed"] = MagicMock(
            side_effect=last_accessed_side_effect
        )
    else:
        patches["secrets_audit.pipeline.get_last_accessed"] = MagicMock(return_value={})
    return patches


# ---------------------------------------------------------------------------
# 7.1 Property 1: Expired token error classification
# Feature: credential-expiry-guard, Property 1: Expired token error classification
# ---------------------------------------------------------------------------


class TestProperty1ExpiredTokenClassification:
    """Property 1: Expired token error classification.

    For any ClientError with an error code in the expired set,
    is_expired_token_error() returns True. For codes outside the set, False.

    **Validates: Requirements 3.1, 4.1, 5.1**
    """

    @given(code=st.sampled_from(["ExpiredTokenException", "ExpiredToken", "RequestExpired"]))
    @settings(max_examples=100)
    def test_expired_codes_return_true(self, code: str) -> None:
        # Feature: credential-expiry-guard, Property 1: Expired token error classification
        exc = _make_client_error(code, "expired")
        assert is_expired_token_error(exc) is True

    @given(code=st.sampled_from(["AccessDeniedException", "ThrottlingException", "NoSuchEntity", "ValidationException"]))
    @settings(max_examples=100)
    def test_non_expired_codes_return_false(self, code: str) -> None:
        # Feature: credential-expiry-guard, Property 1: Expired token error classification
        exc = _make_client_error(code, "other")
        assert is_expired_token_error(exc) is False


# ---------------------------------------------------------------------------
# 7.2 Property 2: Expiry comparison correctness
# Feature: credential-expiry-guard, Property 2: Expiry comparison correctness
# ---------------------------------------------------------------------------


class TestProperty2ExpiryComparisonCorrectness:
    """Property 2: Expiry comparison correctness.

    The pipeline emits a warning iff remaining < threshold.
    No warning when threshold is 0 or expiry is None.

    **Validates: Requirements 1.1, 1.4, 2.2, 2.4**
    """

    @given(
        remaining_minutes=st.integers(min_value=-60, max_value=120),
        threshold=st.integers(min_value=1, max_value=120),
    )
    @settings(max_examples=100)
    def test_warning_emitted_iff_remaining_below_threshold(
        self, remaining_minutes: int, threshold: int
    ) -> None:
        # Feature: credential-expiry-guard, Property 2: Expiry comparison correctness
        # Use a fixed "now" to avoid race between test setup and pipeline execution.
        # The pipeline computes: remaining = (expiry - now()).total_seconds() / 60
        # We patch datetime.now inside the pipeline module to control the comparison.
        fixed_now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        expiry = fixed_now + timedelta(minutes=remaining_minutes)

        session = _mock_session()
        p = _pipeline_patches(session)

        with (
            patch("secrets_audit.pipeline.get_credential_expiry", return_value=expiry),
            patch("secrets_audit.pipeline.datetime") as mock_dt,
        ):
            mock_dt.now.return_value = fixed_now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            stack = [patch(k, v) for k, v in p.items()]
            for s in stack:
                s.start()
            try:
                params = AuditParams(secret="test/secret", expiry_warning_minutes=threshold) # nosec B106
                report = run_audit(params)
            finally:
                for s in stack:
                    s.stop()

        expiry_warnings = [w for w in report.warnings if "credentials expire" in w.lower()]
        if remaining_minutes < threshold:
            assert len(expiry_warnings) >= 1, (
                f"Expected warning when remaining={remaining_minutes} < threshold={threshold}"
            )
        else:
            assert len(expiry_warnings) == 0, (
                f"No warning expected when remaining={remaining_minutes} >= threshold={threshold}"
            )

    def test_no_warning_when_threshold_zero(self) -> None:
        # Feature: credential-expiry-guard, Property 2: Expiry comparison correctness
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(minutes=1)  # would trigger with threshold > 1

        session = _mock_session()
        p = _pipeline_patches(session)

        with patch("secrets_audit.pipeline.get_credential_expiry", return_value=expiry) as mock_expiry:
            stack = [patch(k, v) for k, v in p.items()]
            for s in stack:
                s.start()
            try:
                params = AuditParams(secret="test/secret", expiry_warning_minutes=0) # nosec B106
                report = run_audit(params)
            finally:
                for s in stack:
                    s.stop()

        # get_credential_expiry should not even be called when threshold is 0
        mock_expiry.assert_not_called()
        expiry_warnings = [w for w in report.warnings if "credentials expire" in w.lower()]
        assert len(expiry_warnings) == 0

    def test_no_warning_when_expiry_is_none(self) -> None:
        # Feature: credential-expiry-guard, Property 2: Expiry comparison correctness
        session = _mock_session()
        p = _pipeline_patches(session)

        with patch("secrets_audit.pipeline.get_credential_expiry", return_value=None):
            stack = [patch(k, v) for k, v in p.items()]
            for s in stack:
                s.start()
            try:
                params = AuditParams(secret="test/secret", expiry_warning_minutes=15) # nosec B106
                report = run_audit(params)
            finally:
                for s in stack:
                    s.stop()

        expiry_warnings = [w for w in report.warnings if "credentials expire" in w.lower()]
        assert len(expiry_warnings) == 0


# ---------------------------------------------------------------------------
# 7.3 Property 3: Negative warning minutes rejected
# Feature: credential-expiry-guard, Property 3: Negative warning minutes rejected
# ---------------------------------------------------------------------------


class TestProperty3NegativeWarningMinutesRejected:
    """Property 3: Negative warning minutes rejected.

    For any negative integer, the CLI rejects the value before AWS calls.

    **Validates: Requirements 2.5**
    """

    def test_negative_expiry_warning_rejected(self) -> None:
        # Feature: credential-expiry-guard, Property 3: Negative warning minutes rejected
        runner = CliRunner()
        result = runner.invoke(main, ["--secret", "test/secret", "--expiry-warning-minutes", "-5"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# 7.4 Property 4: Simulation partial results preservation
# Feature: credential-expiry-guard, Property 4: Simulation partial results preservation
# ---------------------------------------------------------------------------


class TestProperty4SimulationPartialResultsPreservation:
    """Property 4: Simulation partial results preservation.

    When ExpiredTokenException occurs at index k, SimulationResult has
    truncated=True, evaluated_count=k, and correct principals.

    **Validates: Requirements 3.1, 6.2, 6.3**
    """

    @given(
        n=st.integers(min_value=1, max_value=10),
        data=st.data(),
    )
    @settings(max_examples=100)
    def test_partial_results_on_expired_token(self, n: int, data: st.DataObject) -> None:
        # Feature: credential-expiry-guard, Property 4: Simulation partial results preservation
        k = data.draw(st.integers(min_value=0, max_value=n - 1))
        principal_arns = [f"arn:aws:iam::123456789012:role/role-{i}" for i in range(n)]

        call_count = 0

        def sim_side_effect(**kwargs):
            nonlocal call_count
            idx = call_count
            call_count += 1
            if idx == k:
                raise _make_client_error("ExpiredTokenException", "Token expired")
            return {"EvaluationResults": []}

        mock_client = MagicMock()
        mock_client.simulate_principal_policy.side_effect = sim_side_effect

        session = MagicMock()
        session.client.return_value = mock_client

        with patch("secrets_audit.resolver._BATCH_SLEEP", 0):
            result = simulate_principal_access(session, principal_arns, _SECRET_ARN)

        assert result.truncated is True
        assert result.evaluated_count == k
        assert result.total_count == n


# ---------------------------------------------------------------------------
# 7.5 Property 5: No further API calls after expired token
# Feature: credential-expiry-guard, Property 5: No further API calls after expired token in simulation
# ---------------------------------------------------------------------------


class TestProperty5NoFurtherApiCallsAfterExpiredToken:
    """Property 5: No further API calls after expired token in simulation.

    After ExpiredTokenException at index k, simulate_principal_policy is
    called exactly k+1 times (indices 0..k).

    **Validates: Requirements 3.4, 7.1**
    """

    @given(
        n=st.integers(min_value=1, max_value=10),
        data=st.data(),
    )
    @settings(max_examples=100)
    def test_call_count_equals_k_plus_one(self, n: int, data: st.DataObject) -> None:
        # Feature: credential-expiry-guard, Property 5: No further API calls after expired token in simulation
        k = data.draw(st.integers(min_value=0, max_value=n - 1))
        principal_arns = [f"arn:aws:iam::123456789012:role/role-{i}" for i in range(n)]

        call_count = 0

        def sim_side_effect(**kwargs):
            nonlocal call_count
            idx = call_count
            call_count += 1
            if idx == k:
                raise _make_client_error("ExpiredTokenException", "Token expired")
            return {"EvaluationResults": []}

        mock_client = MagicMock()
        mock_client.simulate_principal_policy.side_effect = sim_side_effect

        session = MagicMock()
        session.client.return_value = mock_client

        with patch("secrets_audit.resolver._BATCH_SLEEP", 0):
            simulate_principal_access(session, principal_arns, _SECRET_ARN)

        assert mock_client.simulate_principal_policy.call_count == k + 1


# ---------------------------------------------------------------------------
# 7.6 Property 7: CloudTrail expired sets CREDENTIALS_EXPIRED
# Feature: credential-expiry-guard, Property 7: CloudTrail expired sets CREDENTIALS_EXPIRED for all principals
# ---------------------------------------------------------------------------


class TestProperty7CloudTrailExpiredSetsCredentialsExpired:
    """Property 7: CloudTrail expired sets CREDENTIALS_EXPIRED for all principals.

    When get_last_accessed raises ExpiredTokenException, all principals
    get CREDENTIALS_EXPIRED as their last_accessed value.

    **Validates: Requirements 5.1, 5.3**
    """

    def test_all_principals_get_credentials_expired(self) -> None:
        # Feature: credential-expiry-guard, Property 7: CloudTrail expired sets CREDENTIALS_EXPIRED for all principals
        principals = [
            PrincipalAccess(
                principal_type=PrincipalType.IAM_ROLE,
                principal_arn=f"arn:aws:iam::123456789012:role/role-{i}",
                principal_name=f"role-{i}",
                access_level=AccessLevel.READ,
            )
            for i in range(3)
        ]

        sim_result = SimulationResult(
            principals=principals, truncated=False,
            evaluated_count=3, total_count=3,
        )

        session = _mock_session()
        expired_exc = _make_client_error("ExpiredTokenException", "Token expired")
        p = _pipeline_patches(
            session,
            sim_result=sim_result,
            last_accessed_side_effect=expired_exc,
        )

        stack = [patch(k, v) for k, v in p.items()]
        for s in stack:
            s.start()
        try:
            params = AuditParams(secret="test/secret", last_accessed=True) # nosec B106
            report = run_audit(params)
        finally:
            for s in stack:
                s.stop()

        for principal in report.principals:
            assert principal.last_accessed == CREDENTIALS_EXPIRED


# ---------------------------------------------------------------------------
# 7.7 Property 8: Expired token always produces warning with "expired"
# Feature: credential-expiry-guard, Property 8: Expired token always produces warning with "expired" and a report
# ---------------------------------------------------------------------------


class TestProperty8ExpiredTokenProducesWarningWithExpired:
    """Property 8: Expired token always produces warning with "expired" and a report.

    For simulation and CloudTrail phases, an expired token produces a warning
    containing "expired" and a valid AuditReport.

    **Validates: Requirements 6.1, 6.4, 7.4**
    """

    def test_simulation_expired_produces_warning(self) -> None:
        # Feature: credential-expiry-guard, Property 8: Expired token always produces warning with "expired" and a report
        # Simulate expired at index 0 so simulation is truncated
        sim_result = SimulationResult(
            principals=[], truncated=True,
            evaluated_count=0, total_count=5,
        )

        session = _mock_session()
        p = _pipeline_patches(session, sim_result=sim_result)

        stack = [patch(k, v) for k, v in p.items()]
        for s in stack:
            s.start()
        try:
            params = AuditParams(secret="test/secret") # nosec B106
            report = run_audit(params)
        finally:
            for s in stack:
                s.stop()

        assert isinstance(report, AuditReport)
        expired_warnings = [w for w in report.warnings if "expired" in w.lower()]
        assert len(expired_warnings) >= 1

    def test_cloudtrail_expired_produces_warning(self) -> None:
        # Feature: credential-expiry-guard, Property 8: Expired token always produces warning with "expired" and a report
        session = _mock_session()
        expired_exc = _make_client_error("ExpiredTokenException", "Token expired")
        p = _pipeline_patches(session, last_accessed_side_effect=expired_exc)

        stack = [patch(k, v) for k, v in p.items()]
        for s in stack:
            s.start()
        try:
            params = AuditParams(secret="test/secret", last_accessed=True) # nosec B106
            report = run_audit(params)
        finally:
            for s in stack:
                s.stop()

        assert isinstance(report, AuditReport)
        expired_warnings = [w for w in report.warnings if "expired" in w.lower()]
        assert len(expired_warnings) >= 1


# ---------------------------------------------------------------------------
# 7.8 Unit tests for get_credential_expiry
# Feature: credential-expiry-guard
# ---------------------------------------------------------------------------


class TestGetCredentialExpiry:
    """Unit tests for get_credential_expiry.

    **Validates: Requirements 1.1, 1.4, 1.5**
    """

    def test_with_refreshable_creds_returns_datetime(self) -> None:
        # Feature: credential-expiry-guard
        expiry_dt = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        mock_inner = MagicMock()
        mock_inner._expiry_datetime = expiry_dt

        mock_creds = MagicMock()
        mock_creds._credentials = mock_inner
        mock_creds.get_frozen_credentials.return_value = MagicMock()

        session = MagicMock()
        session.get_credentials.return_value = mock_creds

        result = get_credential_expiry(session)
        assert result == expiry_dt

    def test_with_static_creds_returns_none(self) -> None:
        # Feature: credential-expiry-guard
        mock_inner = MagicMock(spec=[])  # no _expiry_datetime attribute

        mock_creds = MagicMock()
        mock_creds._credentials = mock_inner
        mock_creds.get_frozen_credentials.return_value = MagicMock()

        session = MagicMock()
        session.get_credentials.return_value = mock_creds

        result = get_credential_expiry(session)
        assert result is None

    def test_exception_swallowed_returns_none(self) -> None:
        # Feature: credential-expiry-guard
        session = MagicMock()
        session.get_credentials.side_effect = RuntimeError("boom")

        result = get_credential_expiry(session)
        assert result is None


# ---------------------------------------------------------------------------
# 7.9 Unit tests for CLI and warning messages
# Feature: credential-expiry-guard
# ---------------------------------------------------------------------------


class TestCliAndWarningMessages:
    """Unit tests for CLI options and warning message formatting.

    **Validates: Requirements 2.3, 2.5, 3.3, 4.2, 5.2, 8.1, 8.2, 8.3**
    """

    def test_expiry_warning_minutes_default_is_15(self) -> None:
        # Feature: credential-expiry-guard
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "15" in result.output
        assert "expiry-warning-minutes" in result.output

    def test_negative_one_rejected(self) -> None:
        # Feature: credential-expiry-guard
        runner = CliRunner()
        result = runner.invoke(main, ["--secret", "test/secret", "--expiry-warning-minutes", "-1"])
        assert result.exit_code != 0

    def test_zero_skips_check(self) -> None:
        # Feature: credential-expiry-guard
        session = _mock_session()
        p = _pipeline_patches(session)

        with patch("secrets_audit.pipeline.get_credential_expiry") as mock_expiry:
            stack = [patch(k, v) for k, v in p.items()]
            for s in stack:
                s.start()
            try:
                params = AuditParams(secret="test/secret", expiry_warning_minutes=0) # nosec B106
                report = run_audit(params)
            finally:
                for s in stack:
                    s.stop()

        mock_expiry.assert_not_called()

    def test_credentials_expired_status_string(self) -> None:
        # Feature: credential-expiry-guard
        assert CREDENTIALS_EXPIRED == "Unknown (credentials expired)"

    def test_simulation_truncated_warning_format(self) -> None:
        # Feature: credential-expiry-guard
        sim_result = SimulationResult(
            principals=[], truncated=True,
            evaluated_count=42, total_count=100,
        )

        session = _mock_session()
        p = _pipeline_patches(session, sim_result=sim_result)

        stack = [patch(k, v) for k, v in p.items()]
        for s in stack:
            s.start()
        try:
            params = AuditParams(secret="test/secret") # nosec B106
            report = run_audit(params)
        finally:
            for s in stack:
                s.stop()

        truncated_warnings = [w for w in report.warnings if "42 of 100" in w]
        assert len(truncated_warnings) >= 1, (
            f"Expected warning with '42 of 100', got: {report.warnings}"
        )

    def test_cloudtrail_expired_warning_message(self) -> None:
        # Feature: credential-expiry-guard
        session = _mock_session()
        expired_exc = _make_client_error("ExpiredTokenException", "Token expired")
        p = _pipeline_patches(session, last_accessed_side_effect=expired_exc)

        stack = [patch(k, v) for k, v in p.items()]
        for s in stack:
            s.start()
        try:
            params = AuditParams(secret="test/secret", last_accessed=True) # nosec B106
            report = run_audit(params)
        finally:
            for s in stack:
                s.stop()

        ct_warnings = [
            w for w in report.warnings
            if "CloudTrail" in w and "expired" in w.lower()
        ]
        assert len(ct_warnings) >= 1

    def test_quiet_mode_no_progress_but_report_warnings(self) -> None:
        # Feature: credential-expiry-guard
        # When progress=None (quiet mode), warnings still go to report.warnings
        sim_result = SimulationResult(
            principals=[], truncated=True,
            evaluated_count=5, total_count=10,
        )

        session = _mock_session()
        p = _pipeline_patches(session, sim_result=sim_result)

        stack = [patch(k, v) for k, v in p.items()]
        for s in stack:
            s.start()
        try:
            params = AuditParams(secret="test/secret") # nosec B106
            # progress=None simulates quiet mode
            report = run_audit(params, progress=None)
        finally:
            for s in stack:
                s.stop()

        # Warnings should still be in the report
        expired_warnings = [w for w in report.warnings if "expired" in w.lower()]
        assert len(expired_warnings) >= 1
