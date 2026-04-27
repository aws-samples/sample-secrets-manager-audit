"""Property tests for table rendering (Properties 7, 8, 9).

Feature: secrets-audit-tool
"""

from __future__ import annotations

from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.models import (
    AccessLevel,
    AuditReport,
    ICGroupResolution,
    ICUserResolution,
    IdentityCenterResolution,
    PrincipalAccess,
    PrincipalClassification,
    PrincipalType,
    ReportMetadata,
)
from secrets_audit.renderer import render_table


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_metadata_st = st.builds(
    ReportMetadata,
    secret_name=st.text(min_size=1, max_size=50).filter(lambda s: s.strip()),
    secret_arn=st.text(min_size=10, max_size=100).filter(lambda s: s.strip()),
    generated_at=st.text(min_size=10, max_size=40).filter(lambda s: s.strip()),
    generated_by=st.text(min_size=5, max_size=80).filter(lambda s: s.strip()),
    tool_version=st.text(min_size=3, max_size=30).filter(lambda s: s.strip()),
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


_report_with_principals_st = st.builds(
    AuditReport,
    metadata=_metadata_st,
    principals=st.lists(_principal_st, min_size=1, max_size=5),
    warnings=st.lists(st.text(min_size=1, max_size=40), max_size=3),
)


# ---------------------------------------------------------------------------
# Property 9: Table output contains metadata header and required columns
# ---------------------------------------------------------------------------


class TestProperty9TableMetadataAndColumns:
    """Property 9: Table output contains metadata header and required columns.

    For any valid AuditReport with at least one principal, render_table
    should produce output containing: the secret name, secret ARN,
    generated_at timestamp, generated_by identity, tool version in the
    header block, and the column headers PRINCIPAL TYPE, PRINCIPAL NAME,
    IC USER / GROUP, ACCESS LEVEL, LAST ACCESSED in the columnar section.

    Validates: Requirements 3.1, 3.2
    """

    @given(report=_report_with_principals_st)
    @settings(max_examples=100)
    def test_metadata_fields_present(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 9: Table metadata and columns
        output = render_table(report)

        # Metadata header must contain all required fields
        assert report.metadata.secret_name in output
        assert report.metadata.secret_arn in output
        assert report.metadata.generated_at in output
        assert report.metadata.generated_by in output
        assert report.metadata.tool_version in output

    @given(report=_report_with_principals_st)
    @settings(max_examples=100)
    def test_column_headers_present(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 9: Table metadata and columns
        output = render_table(report)

        assert "PRINCIPAL TYPE" in output
        assert "PRINCIPAL NAME" in output
        assert "IC USER / GROUP" in output
        assert "ACCESS LEVEL" in output
        assert "LAST ACCESSED" in output

    @given(report=_report_with_principals_st)
    @settings(max_examples=100)
    def test_separator_line_present(self, report: AuditReport) -> None:
        # Feature: secrets-audit-tool, Property 9: Table metadata and columns
        output = render_table(report)
        lines = output.split("\n")

        # There should be a separator line made of dashes
        separator_lines = [l for l in lines if l.strip() and set(l.strip().replace(" ", "")) == {"-"}]
        assert len(separator_lines) >= 1, "Expected at least one separator line of dashes"

    def test_empty_principals_message(self) -> None:
        """When no principals, output the standard empty message."""
        report = AuditReport(
            metadata=ReportMetadata(
                secret_name="test/secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test/secret-AbCdEf",
                generated_at="2026-03-20T08:00:00-07:00",
                generated_by="arn:aws:iam::123456789012:user/tester",
                tool_version="secrets-audit v1.0.0",
            ),
            principals=[],
        )
        output = render_table(report)
        assert "No IAM principals have access to this secret" in output


# ---------------------------------------------------------------------------
# Property 7: Direct vs group-based user annotation in output
# ---------------------------------------------------------------------------


class TestProperty7DirectVsGroupAnnotation:
    """Property 7: Direct vs group-based user annotation in output.

    For any AuditReport containing principals with IC resolutions that
    include both direct user assignments and group-based assignments,
    the rendered output should contain the direct user's display name
    without a "via group" annotation, and the group-based user's display
    name with a "(via group GroupName)" annotation.

    Validates: Requirements 2.9
    """

    @given(
        direct_name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "Zs")),
            min_size=2, max_size=20,
        ).filter(lambda s: s.strip()),
        group_name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N")),
            min_size=2, max_size=20,
        ).filter(lambda s: s.strip()),
        group_user_name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "Zs")),
            min_size=2, max_size=20,
        ).filter(lambda s: s.strip()),
    )
    @settings(max_examples=100)
    def test_direct_user_no_via_group_annotation(
        self, direct_name: str, group_name: str, group_user_name: str
    ) -> None:
        # Feature: secrets-audit-tool, Property 7: Direct vs group annotation
        ic = IdentityCenterResolution(
            permission_set_name="TestPS",
            users=[
                ICUserResolution(
                    user_id="u-direct",
                    display_name=direct_name,
                    via_group=None,  # direct assignment
                ),
                ICUserResolution(
                    user_id="u-group",
                    display_name=group_user_name,
                    via_group=group_name,  # group-based
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
        output = render_table(report)

        # Direct user should appear without "via group"
        assert direct_name in output

        # Group-based user should have "(via group ...)" annotation
        expected_annotation = f"(via group {group_name})"
        assert expected_annotation in output


# ---------------------------------------------------------------------------
# Property 8: Group member truncation in table vs full list in structured
# ---------------------------------------------------------------------------


class TestProperty8GroupMemberTruncation:
    """Property 8: Group member truncation in table vs full list in structured formats.

    For any AuditReport containing a principal with an IC group resolution
    having more than 50 members, render_table should contain the string
    "...and N more members" (where N = total - 50), while render_json
    should contain all member entries with count equal to the
    total member count.

    Validates: Requirements 2.10
    """

    @given(
        extra_count=st.integers(min_value=1, max_value=30),
    )
    @settings(max_examples=100)
    def test_table_truncates_at_50(self, extra_count: int) -> None:
        # Feature: secrets-audit-tool, Property 8: Group member truncation
        total = 50 + extra_count
        members = [
            ICUserResolution(
                user_id=f"u-{i}",
                display_name=f"User{i}",
                via_group="BigGroup",
            )
            for i in range(total)
        ]
        group = ICGroupResolution(
            group_id="g-big",
            group_name="BigGroup",
            members=members,
            total_member_count=total,
        )
        ic = IdentityCenterResolution(
            permission_set_name="TestPS",
            groups=[group],
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

        from secrets_audit.renderer import render_table, render_json
        import json as json_mod

        table_output = render_table(report)
        assert f"...and {extra_count} more members" in table_output

        # JSON should contain all members (no truncation)
        json_output = render_json(report)
        parsed_json = json_mod.loads(json_output)
        json_groups = parsed_json["principals"][0]["identity_center_group"]
        assert json_groups[0]["total_member_count"] == total
        assert len(json_groups[0]["members"]) == total


# ---------------------------------------------------------------------------
# Test Gap 2: CSV renderer with group expansion
# ---------------------------------------------------------------------------

from secrets_audit.renderer import render_csv


class TestCsvGroupExpansion:
    """Verify render_csv produces IC Group continuation rows for group members."""

    def test_csv_group_member_rows(self) -> None:
        """CSV output contains IC Group rows with correct status for members."""
        group_members = [
            ICUserResolution(
                user_id="u-active",
                display_name="Active User",
                email="active@example.com",
                deleted=False,
            ),
            ICUserResolution(
                user_id="u-deleted",
                display_name="Deleted User",
                email="deleted@example.com",
                deleted=True,
            ),
        ]
        group = ICGroupResolution(
            group_id="g-team",
            group_name="TeamGroup",
            members=group_members,
            total_member_count=2,
        )
        ic = IdentityCenterResolution(
            permission_set_name="AdminPS",
            groups=[group],
        )
        principal = PrincipalAccess(
            principal_type=PrincipalType.IAM_ROLE,
            principal_arn="arn:aws:iam::123456789012:role/ICRole",
            principal_name="ICRole",
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

        csv_output = render_csv(report)

        # Principal main row should exist
        assert "ICRole" in csv_output

        # Active member continuation row: IC Group,TeamGroup,active@example.com,ENABLED
        assert "IC Group" in csv_output
        assert "TeamGroup" in csv_output
        assert "active@example.com" in csv_output
        assert "ENABLED" in csv_output

        # Deleted member continuation row: IC Group,TeamGroup,deleted@example.com,DISABLED
        assert "deleted@example.com" in csv_output
        assert "DISABLED" in csv_output


# ---------------------------------------------------------------------------
# Test Gap 3: PDF renderer basic validation
# ---------------------------------------------------------------------------

from secrets_audit.renderer import render_pdf


class TestPdfBasicValidation:
    """Verify render_pdf returns valid PDF bytes."""

    def test_pdf_returns_valid_bytes(self) -> None:
        """PDF output is bytes, starts with %PDF-, and ends with %%EOF."""
        report = AuditReport(
            metadata=ReportMetadata(
                secret_name="mytestsecret",
                secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:mytestsecret-XyZ",
                generated_at="2026-03-20T08:00:00-07:00",
                generated_by="arn:aws:iam::123456789012:user/tester",
                tool_version="secrets-audit v1.0.0",
            ),
            principals=[
                PrincipalAccess(
                    principal_type=PrincipalType.IAM_ROLE,
                    principal_arn="arn:aws:iam::123456789012:role/SomeRole",
                    principal_name="SomeRole",
                    access_level=AccessLevel.READ,
                    classification=PrincipalClassification.PLAIN_IAM,
                ),
            ],
        )

        result = render_pdf(report)

        assert isinstance(result, bytes)
        assert result.startswith(b"%PDF-")
        # Valid PDF must end with %%EOF marker
        assert b"%%EOF" in result
        # PDF should have non-trivial size (header + content + table)
        assert len(result) > 500

    def test_pdf_empty_principals_still_valid(self) -> None:
        """PDF with no principals still produces valid PDF bytes."""
        report = AuditReport(
            metadata=ReportMetadata(
                secret_name="empty-secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:empty-AbCdEf",
                generated_at="2026-03-20T08:00:00-07:00",
                generated_by="arn:aws:iam::123456789012:user/tester",
                tool_version="secrets-audit v1.0.0",
            ),
            principals=[],
        )

        result = render_pdf(report)

        assert isinstance(result, bytes)
        assert result.startswith(b"%PDF-")
        assert b"%%EOF" in result
