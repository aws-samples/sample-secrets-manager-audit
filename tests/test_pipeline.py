"""Property-based tests for the pipeline module.

Feature: streamlit-web-ui
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from secrets_audit.models import (
    AccessLevel,
    AuditReport,
    PrincipalAccess,
    PrincipalClassification,
    PrincipalType,
    ReportMetadata,
    SecretMetadata,
)
from secrets_audit.pipeline import AuditParams, ValidationError, validate_params
from secrets_audit.renderer import render
from secrets_audit.resolver import SimulationResult
from secrets_audit.validators import (
    ACCOUNT_ID_PATTERN,
    PROFILE_NAME_PATTERN,
    REGION_PATTERN,
    ROLE_ARN_PATTERN,
    SECRET_ARN_PATTERN,
    SECRET_NAME_PATTERN,
)


# ---------------------------------------------------------------------------
# Shared strategies and constants
# ---------------------------------------------------------------------------

_SECRET_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_+=.@-"
_PROFILE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

_valid_account_ids = st.from_regex(r"\d{12}", fullmatch=True)
_valid_role_arns = st.builds(
    lambda acct, name: f"arn:aws:iam::{acct}:role/{name}",
    acct=_valid_account_ids,
    name=st.text(alphabet=_SECRET_NAME_CHARS, min_size=1, max_size=32),
)
_valid_profile_names = st.text(alphabet=_PROFILE_CHARS, min_size=1, max_size=32)
_safe_text = st.text(min_size=1, max_size=30).filter(lambda s: s.strip())

_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf"  # nosec B105


# ---------------------------------------------------------------------------
# Property 1: Mutual exclusivity rejection
# Feature: streamlit-web-ui, Property 1: Mutual exclusivity rejection
# ---------------------------------------------------------------------------


class TestProperty1MutualExclusivityRejection:
    """Property 1: Mutual exclusivity rejection.

    For any AuditParams where master_profile is non-None AND at least one of
    (master_account_id, cross_account_role_arn) is non-None, validate_params
    should raise ValidationError.

    **Validates: Requirements 3.2**
    """

    @given(
        profile=_valid_profile_names,
        account_id=st.one_of(st.none(), _valid_account_ids),
        role_arn=st.one_of(st.none(), _valid_role_arns),
    )
    @settings(max_examples=100)
    def test_mutual_exclusivity_raises(
        self, profile: str, account_id: str | None, role_arn: str | None
    ) -> None:
        # Feature: streamlit-web-ui, Property 1: Mutual exclusivity rejection
        assume(account_id is not None or role_arn is not None)

        params = AuditParams(
            secret="my-valid-secret",  # nosec B106
            master_profile=profile,
            master_account_id=account_id,
            cross_account_role_arn=role_arn,
        )
        with pytest.raises(ValidationError):
            validate_params(params)


# ---------------------------------------------------------------------------
# Property 2: Validation agreement between pipeline and CLI validators
# Feature: streamlit-web-ui, Property 2: Validation agreement
# ---------------------------------------------------------------------------


class TestProperty2ValidationAgreement:
    """Property 2: Validation agreement between pipeline and CLI validators.

    For any string, the pipeline's validate_params regex checks should accept
    or reject the same inputs as the corresponding validators.py functions.

    **Validates: Requirements 3.3, 8.3**
    """

    @given(value=st.text(max_size=100))
    @settings(max_examples=100)
    def test_secret_field_agreement(self, value: str) -> None:
        # Feature: streamlit-web-ui, Property 2: Validation agreement
        validators_accepts = (
            bool(SECRET_NAME_PATTERN.match(value))
            or bool(SECRET_ARN_PATTERN.match(value))
        )

        params = AuditParams(secret=value)  # nosec B106
        try:
            validate_params(params)
            pipeline_accepts = True
        except ValidationError:
            pipeline_accepts = False

        assert validators_accepts == pipeline_accepts, (
            f"Disagreement on secret={value!r}: "
            f"validators={validators_accepts}, pipeline={pipeline_accepts}"
        )

    @given(value=st.text(max_size=100))
    @settings(max_examples=100)
    def test_account_id_field_agreement(self, value: str) -> None:
        # Feature: streamlit-web-ui, Property 2: Validation agreement
        validators_accepts = bool(ACCOUNT_ID_PATTERN.match(value))

        params = AuditParams(secret="my-valid-secret", master_account_id=value)  # nosec B106
        try:
            validate_params(params)
            pipeline_accepts = True
        except ValidationError:
            pipeline_accepts = False

        assert validators_accepts == pipeline_accepts, (
            f"Disagreement on account_id={value!r}: "
            f"validators={validators_accepts}, pipeline={pipeline_accepts}"
        )

    @given(value=st.text(max_size=100))
    @settings(max_examples=100)
    def test_role_arn_field_agreement(self, value: str) -> None:
        # Feature: streamlit-web-ui, Property 2: Validation agreement
        validators_accepts = bool(ROLE_ARN_PATTERN.match(value))

        params = AuditParams(secret="my-valid-secret", cross_account_role_arn=value)  # nosec B106
        try:
            validate_params(params)
            pipeline_accepts = True
        except ValidationError:
            pipeline_accepts = False

        assert validators_accepts == pipeline_accepts, (
            f"Disagreement on role_arn={value!r}: "
            f"validators={validators_accepts}, pipeline={pipeline_accepts}"
        )

    @given(value=st.text(max_size=100))
    @settings(max_examples=100)
    def test_region_field_agreement(self, value: str) -> None:
        # Feature: streamlit-web-ui, Property 2: Validation agreement
        validators_accepts = bool(REGION_PATTERN.match(value))

        params = AuditParams(secret="my-valid-secret", region=value)  # nosec B106
        try:
            validate_params(params)
            pipeline_accepts = True
        except ValidationError:
            pipeline_accepts = False

        assert validators_accepts == pipeline_accepts, (
            f"Disagreement on region={value!r}: "
            f"validators={validators_accepts}, pipeline={pipeline_accepts}"
        )

    @given(value=st.text(max_size=100))
    @settings(max_examples=100)
    def test_profile_name_field_agreement(self, value: str) -> None:
        # Feature: streamlit-web-ui, Property 2: Validation agreement
        validators_accepts = bool(PROFILE_NAME_PATTERN.match(value))

        params = AuditParams(secret="my-valid-secret", master_profile=value)  # nosec B106
        try:
            validate_params(params)
            pipeline_accepts = True
        except ValidationError:
            pipeline_accepts = False

        assert validators_accepts == pipeline_accepts, (
            f"Disagreement on profile_name={value!r}: "
            f"validators={validators_accepts}, pipeline={pipeline_accepts}"
        )


# ---------------------------------------------------------------------------
# Property 3: Report metadata completeness
# Feature: streamlit-web-ui, Property 3: Report metadata completeness
# ---------------------------------------------------------------------------


class TestProperty3ReportMetadataCompleteness:
    """Property 3: Report metadata completeness.

    For any AuditReport, the metadata field should have non-empty values for
    secret_name, secret_arn, generated_at, generated_by, and tool_version.

    **Validates: Requirements 5.1**
    """

    @given(
        secret_name=_safe_text,
        secret_arn=_safe_text,
        generated_at=_safe_text,
        generated_by=_safe_text,
        tool_version=_safe_text,
        region=st.one_of(st.none(), _safe_text),
    )
    @settings(max_examples=100)
    def test_metadata_fields_non_empty(
        self,
        secret_name: str,
        secret_arn: str,
        generated_at: str,
        generated_by: str,
        tool_version: str,
        region: str | None,
    ) -> None:
        # Feature: streamlit-web-ui, Property 3: Report metadata completeness
        metadata = ReportMetadata(
            secret_name=secret_name,
            secret_arn=secret_arn,
            generated_at=generated_at,
            generated_by=generated_by,
            tool_version=tool_version,
            region=region,
        )
        report = AuditReport(metadata=metadata)

        assert report.metadata.secret_name, "secret_name must be non-empty"
        assert report.metadata.secret_arn, "secret_arn must be non-empty"
        assert report.metadata.generated_at, "generated_at must be non-empty"
        assert report.metadata.generated_by, "generated_by must be non-empty"
        assert report.metadata.tool_version, "tool_version must be non-empty"


# ---------------------------------------------------------------------------
# Helpers for pipeline mocking (Properties 5 and 6)
# ---------------------------------------------------------------------------


def _mock_session() -> MagicMock:
    s = MagicMock()
    s.region_name = "us-east-1"
    return s


# ---------------------------------------------------------------------------
# Property 5: Progress callback covers major pipeline steps
# Feature: streamlit-web-ui, Property 5: Progress callback covers major steps
# ---------------------------------------------------------------------------


class TestProperty5ProgressCallbackCoverage:
    """Property 5: Progress callback covers major pipeline steps.

    Run run_audit() with mocked AWS clients and a recording callback. Assert
    the collected messages collectively reference principal simulation.

    **Validates: Requirements 7.1, 7.3**
    """

    def test_progress_callback_receives_simulation_messages(self) -> None:
        # Feature: streamlit-web-ui, Property 5: Progress callback covers major steps
        from secrets_audit.pipeline import run_audit

        mock_session = _mock_session()
        messages: list[str] = []

        role_arns = [f"arn:aws:iam::123456789012:role/role-{i}" for i in range(5)]
        user_arns = [f"arn:aws:iam::123456789012:user/user-{i}" for i in range(3)]

        with (
            patch("secrets_audit.pipeline.create_prod_session", return_value=mock_session),
            patch(
                "secrets_audit.pipeline.get_caller_identity",
                return_value="arn:aws:iam::123456789012:user/tester",
            ),
            patch(
                "secrets_audit.pipeline.resolve_secret",
                return_value=SecretMetadata(name="test/secret", arn=_SECRET_ARN),
            ),
            patch("secrets_audit.pipeline.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.pipeline.list_iam_roles", return_value=role_arns),
            patch("secrets_audit.pipeline.list_iam_users", return_value=user_arns),
            patch("secrets_audit.pipeline.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.pipeline.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.pipeline.get_last_accessed", return_value={}),
        ):
            params = AuditParams(secret="my-valid-secret")  # nosec B106
            run_audit(params, progress=messages.append)

        sim_messages = [m for m in messages if "Simulating" in m or "Simulation" in m]
        assert len(sim_messages) >= 1, (
            f"Expected at least one simulation progress message, got: {messages}"
        )

        complete_msgs = [m for m in messages if "Simulation complete" in m]
        assert len(complete_msgs) >= 1, (
            f"Expected simulation complete message, got: {messages}"
        )


# ---------------------------------------------------------------------------
# Property 6: Simulation progress includes count
# Feature: streamlit-web-ui, Property 6: Simulation progress includes count
# ---------------------------------------------------------------------------


class TestProperty6SimulationProgressCount:
    """Property 6: Simulation progress includes count.

    Run run_audit() with mocked AWS clients returning N principals. Assert at
    least one progress message matches "Simulating principals... (N/M)".

    **Validates: Requirements 7.2**
    """

    def test_simulation_progress_includes_count_pattern(self) -> None:
        # Feature: streamlit-web-ui, Property 6: Simulation progress includes count
        from secrets_audit.pipeline import run_audit

        mock_session = _mock_session()
        messages: list[str] = []

        # 25 principals triggers interval=10, so we get messages at idx 10, 20
        role_arns = [f"arn:aws:iam::123456789012:role/role-{i}" for i in range(25)]

        mock_iam_client = MagicMock()
        mock_iam_client.simulate_principal_policy.return_value = {"EvaluationResults": []}
        mock_session.client.return_value = mock_iam_client

        with (
            patch("secrets_audit.pipeline.create_prod_session", return_value=mock_session),
            patch(
                "secrets_audit.pipeline.get_caller_identity",
                return_value="arn:aws:iam::123456789012:user/tester",
            ),
            patch(
                "secrets_audit.pipeline.resolve_secret",
                return_value=SecretMetadata(name="test/secret", arn=_SECRET_ARN),
            ),
            patch("secrets_audit.pipeline.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.pipeline.list_iam_roles", return_value=role_arns),
            patch("secrets_audit.pipeline.list_iam_users", return_value=[]),
            patch("secrets_audit.resolver._BATCH_SLEEP", 0),
            patch("secrets_audit.pipeline.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.pipeline.get_last_accessed", return_value={}),
        ):
            params = AuditParams(secret="my-valid-secret")  # nosec B106
            run_audit(params, progress=messages.append)

        count_pattern = re.compile(r"Simulating principals\.\.\. \(\d+/\d+\)")
        count_msgs = [m for m in messages if count_pattern.search(m)]
        assert len(count_msgs) >= 1, (
            f"Expected at least one 'Simulating principals... (N/M)' message, "
            f"got messages: {messages}"
        )


# ---------------------------------------------------------------------------
# Property 7: Output safety — no credentials or raw policy data
# Feature: streamlit-web-ui, Property 7: Output safety
# ---------------------------------------------------------------------------

_AKIA_PATTERN = re.compile(r"AKIA[A-Z0-9]{16}")
_SESSION_TOKEN_KEYS = ["SessionToken", "SecretAccessKey", "AccessKeyId"]

_metadata_st = st.builds(
    ReportMetadata,
    secret_name=_safe_text,
    secret_arn=_safe_text,
    generated_at=_safe_text,
    generated_by=_safe_text,
    tool_version=_safe_text,
)

_principal_st = st.builds(
    PrincipalAccess,
    principal_type=st.sampled_from(PrincipalType),
    principal_arn=_safe_text,
    principal_name=_safe_text,
    access_level=st.sampled_from(AccessLevel),
    allowed_actions=st.lists(
        st.sampled_from([
            "secretsmanager:GetSecretValue",
            "secretsmanager:PutSecretValue",
            "secretsmanager:DeleteSecret",
            "secretsmanager:DescribeSecret",
        ]),
        min_size=0,
        max_size=4,
    ),
    classification=st.sampled_from(PrincipalClassification),
)

_report_st = st.builds(
    AuditReport,
    metadata=_metadata_st,
    principals=st.lists(_principal_st, min_size=0, max_size=5),
    warnings=st.lists(_safe_text, max_size=3),
)


class TestProperty7OutputSafety:
    """Property 7: Output safety — no credentials or raw policy data in rendered output.

    For any AuditReport and any output format, the rendered string should not
    contain AWS access key patterns (AKIA...), session token patterns, the
    literal key "allowed_actions", or raw IAM policy JSON documents.

    **Validates: Requirements 8.2, 8.5**
    """

    @given(report=_report_st, fmt=st.sampled_from(["table", "json", "csv"]))
    @settings(max_examples=100)
    def test_no_akia_pattern_in_output(self, report: AuditReport, fmt: str) -> None:
        # Feature: streamlit-web-ui, Property 7: Output safety
        output = render(report, fmt)
        assert not _AKIA_PATTERN.search(output), (
            f"Output in {fmt} format contains AKIA access key pattern"
        )

    @given(report=_report_st, fmt=st.sampled_from(["table", "json", "csv"]))
    @settings(max_examples=100)
    def test_no_session_token_keys_in_output(self, report: AuditReport, fmt: str) -> None:
        # Feature: streamlit-web-ui, Property 7: Output safety
        output = render(report, fmt)
        for key in _SESSION_TOKEN_KEYS:
            assert key not in output, (
                f"Output in {fmt} format contains forbidden key: {key}"
            )

    @given(report=_report_st, fmt=st.sampled_from(["table", "json", "csv"]))
    @settings(max_examples=100)
    def test_no_allowed_actions_in_output(self, report: AuditReport, fmt: str) -> None:
        # Feature: streamlit-web-ui, Property 7: Output safety
        output = render(report, fmt)
        assert "allowed_actions" not in output, (
            f"Output in {fmt} format contains 'allowed_actions'"
        )

    @given(report=_report_st, fmt=st.sampled_from(["table", "json", "csv"]))
    @settings(max_examples=100)
    def test_no_raw_policy_json_in_output(self, report: AuditReport, fmt: str) -> None:
        # Feature: streamlit-web-ui, Property 7: Output safety
        output = render(report, fmt)
        for line in output.split("\n"):
            has_statement = '"Statement"' in line or "'Statement'" in line
            has_effect = '"Effect"' in line or "'Effect'" in line
            assert not (has_statement and has_effect), (
                f"{fmt} output contains what looks like raw IAM policy JSON: "
                f"{line[:200]}"
            )


class TestProperty7OutputSafetyPdf:
    """Property 7 (PDF): Output safety for PDF binary output.

    **Validates: Requirements 8.2, 8.5**
    """

    @given(report=_report_st)
    @settings(max_examples=50, deadline=None)
    def test_pdf_no_akia_pattern(self, report: AuditReport) -> None:
        output = render(report, "pdf")
        assert isinstance(output, bytes)
        text = output.decode("latin-1")
        assert not _AKIA_PATTERN.search(text), (
            "PDF output contains AKIA access key pattern"
        )

    @given(report=_report_st)
    @settings(max_examples=50, deadline=None)
    def test_pdf_no_session_token_keys(self, report: AuditReport) -> None:
        output = render(report, "pdf")
        text = output.decode("latin-1")
        for key in _SESSION_TOKEN_KEYS:
            assert key not in text, (
                f"PDF output contains forbidden key: {key}"
            )
