"""Property tests for structured (JSON) rendering (Properties 7, 10).

Feature: secrets-audit-tool
"""

from __future__ import annotations

import json as json_mod
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.models import (
    AccessLevel,
    AuditReport,
    ICUserResolution,
    IdentityCenterResolution,
    PrincipalAccess,
    PrincipalClassification,
    PrincipalType,
    ReportMetadata,
)
from secrets_audit.renderer import render_json


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_safe_text = st.text(min_size=1, max_size=50).filter(lambda s: s.strip())

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
    principal_arn=st.text(min_size=10, max_size=80).filter(lambda s: s.strip()),
    principal_name=st.text(min_size=1, max_size=50).filter(lambda s: s.strip()),
    access_level=st.sampled_from(AccessLevel),
    classification=st.just(PrincipalClassification.PLAIN_IAM),
    last_accessed=st.one_of(
        st.none(),
        st.just("No recent access (>90 days)"),
        st.datetimes(
            min_value=datetime(2020, 1, 1),
            max_value=datetime(2030, 1, 1),
            timezones=st.just(timezone.utc),
        ),
    ),
)


_report_st = st.builds(
    AuditReport,
    metadata=_metadata_st,
    principals=st.lists(_principal_st, min_size=0, max_size=5),
    warnings=st.lists(st.text(min_size=1, max_size=40), max_size=3),
)


# ---------------------------------------------------------------------------
# Property 10: JSON round-trip preserves report structure
# ---------------------------------------------------------------------------


class TestProperty10JsonRoundTrip:
    """Property 10: JSON serialization round-trip preserves report structure.

    For any valid AuditReport, rendering to JSON and parsing back should
    produce a dictionary containing the keys secret_name, secret_arn,
    generated_at, generated_by, tool_version, and principals (a list with
    length equal to the number of principals). Additionally, render_json
    output should be valid JSON parseable by json.loads.

    Validates: Requirements 3.1, 3.3, 3.4
    """

    @given(report=_report_st)
    @settings(max_examples=100)
    def test_json_round_trip_keys(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 10: JSON round-trip
        json_output = render_json(report)

        # Must be valid JSON
        parsed = json_mod.loads(json_output)

        assert isinstance(parsed, dict)
        assert "secret_name" in parsed
        assert "secret_arn" in parsed
        assert "generated_at" in parsed
        assert "generated_by" in parsed
        assert "tool_version" in parsed
        assert "principals" in parsed
        assert len(parsed["principals"]) == len(report.principals)

    @given(report=_report_st)
    @settings(max_examples=100)
    def test_json_metadata_values_match(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 10: JSON round-trip
        json_output = render_json(report)
        parsed = json_mod.loads(json_output)

        assert parsed["secret_name"] == report.metadata.secret_name
        assert parsed["secret_arn"] == report.metadata.secret_arn
        assert parsed["generated_at"] == report.metadata.generated_at
        assert parsed["generated_by"] == report.metadata.generated_by
        assert parsed["tool_version"] == report.metadata.tool_version


# ---------------------------------------------------------------------------
# Property 7 (structured): Direct vs group annotation in JSON
# ---------------------------------------------------------------------------


class TestProperty7StructuredDirectVsGroup:
    """Property 7 (structured): Direct vs group-based user annotation.

    In JSON output, direct users should NOT have a via_group key,
    while group-based users should have via_group set to the group name.

    Validates: Requirements 2.9
    """

    def test_direct_user_no_via_group_in_json(self) -> None:
        # Feature: secrets-audit-tool, Property 7: Direct vs group annotation
        ic = IdentityCenterResolution(
            permission_set_name="TestPS",
            users=[
                ICUserResolution(
                    user_id="u-direct",
                    display_name="DirectUser",
                    via_group=None,
                ),
                ICUserResolution(
                    user_id="u-group",
                    display_name="GroupUser",
                    via_group="DevTeam",
                ),
            ],
        )
        principal = PrincipalAccess(
            principal_type=PrincipalType.IAM_ROLE,
            principal_arn="arn:aws:iam::123456789012:role/TestRole",
            principal_name="TestRole",
            access_level=AccessLevel.READ,
            classification=PrincipalClassification.IDENTITY_CENTER,
            ic_resolution=ic,
        )
        report = AuditReport(
            metadata=ReportMetadata(
                secret_name="test/secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
                generated_at="2026-03-20T08:00:00-07:00",
                generated_by="arn:aws:iam::123456789012:user/tester",
                tool_version="secrets-audit v1.0.0",
            ),
            principals=[principal],
        )

        json_output = render_json(report)
        parsed = json_mod.loads(json_output)
        users = parsed["principals"][0]["identity_center_user"]

        direct = [u for u in users if u["user_id"] == "u-direct"][0]
        group_based = [u for u in users if u["user_id"] == "u-group"][0]

        # Direct user should not have via_group key
        assert "via_group" not in direct
        # Group-based user should have via_group
        assert group_based["via_group"] == "DevTeam"
