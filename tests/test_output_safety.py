"""Property test for output safety (Property 11).

Feature: secrets-audit-tool
"""

from __future__ import annotations

from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.models import (
    AccessLevel,
    AuditReport,
    PrincipalAccess,
    PrincipalClassification,
    PrincipalType,
    ReportMetadata,
)
from secrets_audit.renderer import render, render_csv, render_json, render_table

# Forbidden substrings that must never appear in rendered output
_FORBIDDEN = [
    "SecretString",
    "SecretBinary",
    "AccessKeyId",
    "SecretAccessKey",
    "SessionToken",
]


# Strategy: generate reports with adversarial field values that might
# trick a naive renderer into leaking forbidden content.
_safe_text = st.text(min_size=1, max_size=30).filter(lambda s: s.strip())

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
            "secretsmanager:CreateSecret",
            "secretsmanager:UpdateSecret",
        ]),
        min_size=1,
        max_size=4,
    ),
    classification=st.just(PrincipalClassification.PLAIN_IAM),
)

_report_st = st.builds(
    AuditReport,
    metadata=_metadata_st,
    principals=st.lists(_principal_st, min_size=0, max_size=5),
    warnings=st.lists(_safe_text, max_size=3),
)


class TestProperty11OutputSafety:
    """Property 11: Output safety — no secrets, credentials, or raw policies.

    For any valid AuditReport (including reports with principals that have
    allowed_actions populated), the rendered output in all text formats
    should never contain the substrings "SecretString", "SecretBinary",
    "AccessKeyId", "SecretAccessKey", "SessionToken", or any JSON string
    that looks like a full IAM policy document (containing both "Statement"
    and "Effect" keys on the same line).

    Validates: Requirements 3.10
    """

    @given(report=_report_st)
    @settings(max_examples=100)
    def test_table_no_forbidden_strings(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 11: Output safety
        output = render_table(report)
        for forbidden in _FORBIDDEN:
            assert forbidden not in output, (
                f"Table output contains forbidden string: {forbidden}"
            )

    @given(report=_report_st)
    @settings(max_examples=100)
    def test_csv_no_forbidden_strings(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 11: Output safety
        output = render_csv(report)
        for forbidden in _FORBIDDEN:
            assert forbidden not in output, (
                f"CSV output contains forbidden string: {forbidden}"
            )

    @given(report=_report_st)
    @settings(max_examples=100)
    def test_json_no_forbidden_strings(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 11: Output safety
        output = render_json(report)
        for forbidden in _FORBIDDEN:
            assert forbidden not in output, (
                f"JSON output contains forbidden string: {forbidden}"
            )

    @given(report=_report_st)
    @settings(max_examples=100)
    def test_no_raw_policy_document_in_output(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 11: Output safety
        # A raw IAM policy doc would have both "Statement" and "Effect"
        for fmt in ("table", "json", "csv"):
            output = render(report, fmt)
            for line in output.split("\n"):
                has_statement = '"Statement"' in line or "'Statement'" in line
                has_effect = '"Effect"' in line or "'Effect'" in line
                assert not (has_statement and has_effect), (
                    f"{fmt} output contains what looks like a raw IAM policy "
                    f"document on a single line: {line[:200]}"
                )

    @given(report=_report_st)
    @settings(max_examples=100)
    def test_allowed_actions_not_in_structured_output(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 11: Output safety
        # The renderer intentionally omits allowed_actions from structured output
        import json as json_mod

        json_output = render_json(report)
        parsed_json = json_mod.loads(json_output)
        for p in parsed_json.get("principals", []):
            assert "allowed_actions" not in p, (
                "JSON output should not contain allowed_actions"
            )
