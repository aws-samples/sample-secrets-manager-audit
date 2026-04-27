"""Property-based tests for the version-metadata feature.

Tests cover:
- Property 1: Flag-off skips version retrieval and leaves versions empty
- Property 2: Version fetcher maps all API response fields correctly
- Property 3: Pagination collects all versions across all pages
- Property 4: Table rendering displays version section correctly
- Property 5: Empty versions list renders correctly across all formats
- Property 6: Structured output contains version entries with correct types
- Property 7: JSON/YAML round-trip preserves version data
- Unit tests for edge cases and error handling
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import botocore.exceptions
from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.cli import main
from secrets_audit.models import (
    AccessLevel,
    AuditReport,
    PrincipalAccess,
    PrincipalClassification,
    PrincipalType,
    ReportMetadata,
    SecretMetadata,
    SecretVersionInfo,
)
from secrets_audit.renderer import render_json, render_table
from secrets_audit.resolver import SimulationResult, list_secret_versions

# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------

_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf"  # nosec B105

_ISO8601_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+\d{2}:\d{2}|Z)$"
)


def _mock_session() -> MagicMock:
    s = MagicMock()
    s.region_name = "us-east-1"
    return s


def _build_principal(name: str) -> PrincipalAccess:
    return PrincipalAccess(
        principal_type=PrincipalType.IAM_ROLE,
        principal_arn=f"arn:aws:iam::123456789012:role/{name}",
        principal_name=name,
        access_level=AccessLevel.READ,
        classification=PrincipalClassification.PLAIN_IAM,
        policy_source="identity_policy",
    )


def _pipeline_patches(mock_session, principals=None):
    return (
        patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
        patch("secrets_audit.cli.validate_account_id", return_value=None),
        patch("secrets_audit.cli.validate_role_arn", return_value=None),
        patch("secrets_audit.cli.validate_region", return_value=None),
        patch("secrets_audit.cli.validate_profile_name", return_value=None),
        patch("secrets_audit.cli.create_prod_session", return_value=mock_session),
        patch("secrets_audit.cli.get_caller_identity",
              return_value="arn:aws:iam::123456789012:user/tester"),
        patch("secrets_audit.cli.resolve_secret",
              return_value=SecretMetadata(name="test/secret", arn=_SECRET_ARN)),
        patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
        patch("secrets_audit.cli.list_iam_roles", return_value=[]),
        patch("secrets_audit.cli.list_iam_users", return_value=[]),
        patch("secrets_audit.cli.simulate_principal_access",
              return_value=SimulationResult(principals=principals or [])),
        patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
        patch("secrets_audit.cli.get_last_accessed", return_value={}),
        patch("secrets_audit.cli.list_secret_versions", return_value=([], [])),
    )


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_principal_names = st.from_regex(r"[a-zA-Z][a-zA-Z0-9_-]{0,19}", fullmatch=True)

_staging_labels = st.lists(
    st.sampled_from(["AWSCURRENT", "AWSPREVIOUS", "AWSPENDING"]),
    min_size=0, max_size=3, unique=True,
)

_created_dates = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2025, 12, 31),
    timezones=st.just(timezone.utc),
)

_version_info_st = st.builds(
    SecretVersionInfo,
    version_id=st.uuids().map(str),
    staging_labels=_staging_labels,
    created_date=st.one_of(st.none(), _created_dates),
)

_metadata_st = st.builds(
    ReportMetadata,
    secret_name=st.text(min_size=1, max_size=50).filter(lambda s: s.strip()),
    secret_arn=st.text(min_size=10, max_size=100).filter(lambda s: s.strip()),
    generated_at=st.text(min_size=10, max_size=40).filter(lambda s: s.strip()),
    generated_by=st.text(min_size=5, max_size=80).filter(lambda s: s.strip()),
    tool_version=st.text(min_size=3, max_size=30).filter(lambda s: s.strip()),
)

_report_with_versions_st = st.builds(
    AuditReport,
    metadata=_metadata_st,
    principals=st.just([]),
    warnings=st.just([]),
    versions=st.lists(_version_info_st, min_size=1, max_size=5),
)

_report_empty_versions_st = st.builds(
    AuditReport,
    metadata=_metadata_st,
    principals=st.just([]),
    warnings=st.just([]),
    versions=st.just([]),
)

_version_entry = st.fixed_dictionaries({
    "VersionId": st.uuids().map(str),
    "VersionStages": _staging_labels,
    "CreatedDate": _created_dates,
})


# ---------------------------------------------------------------------------
# Task 2.2: Property 1 -- Flag-off skips version retrieval
# Feature: version-metadata, Property 1
# ---------------------------------------------------------------------------


class TestProperty1FlagOffSkipsVersionRetrieval:
    """Property 1: Flag-off skips version retrieval and leaves versions empty.

    **Validates: Requirements 1.2, 6.2**
    """

    @given(names=st.lists(_principal_names, min_size=0, max_size=5, unique=True))
    @settings(max_examples=100)
    def test_flag_off_skips_version_retrieval(self, names: list[str]) -> None:
        # Feature: version-metadata, Property 1
        principals = [_build_principal(n) for n in names]
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)
        patches = _pipeline_patches(session, principals=principals)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
            patches[14] as mock_list_versions,
        ):
            result = runner.invoke(
                main, ["--secret", "test/secret", "--output", "json"]
            )
        assert result.exit_code == 0, f"CLI failed: {result.output}"
        mock_list_versions.assert_not_called()
        parsed = json.loads(result.output)
        assert parsed["versions"] == []


# ---------------------------------------------------------------------------
# Task 2.3: Property 2 -- Version fetcher maps all API response fields correctly
# Feature: version-metadata, Property 2
# ---------------------------------------------------------------------------


class TestProperty2VersionFetcherFieldMapping:
    """Property 2: Version fetcher maps all API response fields correctly.

    **Validates: Requirements 2.2**
    """

    @given(entries=st.lists(_version_entry, min_size=0, max_size=10))
    @settings(max_examples=100)
    def test_version_fetcher_maps_fields_correctly(self, entries: list[dict]) -> None:
        # Feature: version-metadata, Property 2
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_client.list_secret_version_ids.return_value = {"Versions": entries}
        versions, warnings = list_secret_versions(mock_session, _SECRET_ARN)
        assert len(versions) == len(entries)
        assert warnings == []
        for version, entry in zip(versions, entries):
            assert version.version_id == entry["VersionId"]
            assert version.staging_labels == entry["VersionStages"]
            assert version.created_date == entry["CreatedDate"]


# ---------------------------------------------------------------------------
# Task 2.4: Property 3 -- Pagination collects all versions across all pages
# Feature: version-metadata, Property 3
# ---------------------------------------------------------------------------


class TestProperty3PaginationCollectsAllVersions:
    """Property 3: Pagination collects all versions across all pages.

    **Validates: Requirements 2.3**
    """

    @given(page_sizes=st.lists(st.integers(min_value=0, max_value=10), min_size=1, max_size=5))
    @settings(max_examples=100)
    def test_pagination_collects_all_versions(self, page_sizes: list[int]) -> None:
        # Feature: version-metadata, Property 3
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        num_pages = len(page_sizes)
        responses = []
        for page_idx, size in enumerate(page_sizes):
            versions_list = [
                {"VersionId": str(uuid.uuid4()), "VersionStages": ["AWSCURRENT"],
                 "CreatedDate": datetime(2025, 1, 1, tzinfo=timezone.utc)}
                for _ in range(size)
            ]
            resp = {"Versions": versions_list}
            if page_idx < num_pages - 1:
                resp["NextToken"] = f"token-{page_idx + 1}"
            responses.append(resp)
        mock_client.list_secret_version_ids.side_effect = responses
        versions, warnings = list_secret_versions(mock_session, _SECRET_ARN)
        assert len(versions) == sum(page_sizes)
        assert warnings == []
        assert mock_client.list_secret_version_ids.call_count == num_pages


# ---------------------------------------------------------------------------
# Task 5.3: Property 4 -- Table rendering displays version section correctly
# Feature: version-metadata, Property 4
# ---------------------------------------------------------------------------


class TestProperty4TableVersionSection:
    """Property 4: Table rendering displays version section with correct columns and formatting.

    **Validates: Requirements 4.1, 4.2, 4.4, 4.5**
    """

    @given(report=_report_with_versions_st)
    @settings(max_examples=100)
    def test_table_version_section_present(self, report: AuditReport) -> None:
        # Feature: version-metadata, Property 4
        output = render_table(report)
        assert "SECRET VERSIONS" in output
        assert "VERSION ID" in output
        assert "STAGING LABELS" in output
        assert "CREATED DATE" in output
        for v in report.versions:
            assert v.version_id in output
            if v.staging_labels:
                labels_str = ", ".join(v.staging_labels)
                assert labels_str in output
            if v.created_date is not None:
                expected_date = v.created_date.strftime("%Y-%m-%d %H:%M UTC")
                assert expected_date in output
            else:
                assert "N/A" in output


# ---------------------------------------------------------------------------
# Task 5.4: Property 5 -- Empty versions list renders correctly
# Feature: version-metadata, Property 5
# ---------------------------------------------------------------------------


class TestProperty5EmptyVersionsRendering:
    """Property 5: Empty versions list renders correctly across all formats.

    **Validates: Requirements 4.3, 5.3**
    """

    @given(report=_report_empty_versions_st)
    @settings(max_examples=100)
    def test_empty_versions_no_section_in_table(self, report: AuditReport) -> None:
        # Feature: version-metadata, Property 5
        output = render_table(report)
        assert "SECRET VERSIONS" not in output

    @given(report=_report_empty_versions_st)
    @settings(max_examples=100)
    def test_empty_versions_json_has_empty_list(self, report: AuditReport) -> None:
        # Feature: version-metadata, Property 5
        output = render_json(report)
        parsed = json.loads(output)
        assert parsed["versions"] == []


# ---------------------------------------------------------------------------
# Task 5.5: Property 6 -- Structured output version entries with correct types
# Feature: version-metadata, Property 6
# ---------------------------------------------------------------------------


class TestProperty6StructuredOutputVersionTypes:
    """Property 6: Structured output contains version entries with correct types and ISO dates.

    **Validates: Requirements 5.1, 5.2, 5.4**
    """

    @given(report=_report_with_versions_st)
    @settings(max_examples=100)
    def test_json_version_entry_types(self, report: AuditReport) -> None:
        # Feature: version-metadata, Property 6
        output = render_json(report)
        parsed = json.loads(output)
        assert len(parsed["versions"]) == len(report.versions)
        for entry, original in zip(parsed["versions"], report.versions):
            assert isinstance(entry["version_id"], str)
            assert entry["version_id"] == original.version_id
            assert isinstance(entry["staging_labels"], list)
            for label in entry["staging_labels"]:
                assert isinstance(label, str)
            if original.created_date is not None:
                assert isinstance(entry["created_date"], str)
                assert _ISO8601_PATTERN.match(entry["created_date"])
            else:
                assert entry["created_date"] is None


# ---------------------------------------------------------------------------
# Task 5.6: Property 7 -- JSON/YAML round-trip preserves version data
# Feature: version-metadata, Property 7
# ---------------------------------------------------------------------------


class TestProperty7VersionRoundTrip:
    """Property 7: JSON/YAML round-trip preserves version data.

    **Validates: Requirements 5.1, 5.2**
    """

    @given(report=_report_with_versions_st)
    @settings(max_examples=100)
    def test_json_round_trip_preserves_versions(self, report: AuditReport) -> None:
        # Feature: version-metadata, Property 7
        output = render_json(report)
        parsed = json.loads(output)
        assert len(parsed["versions"]) == len(report.versions)
        for entry, original in zip(parsed["versions"], report.versions):
            assert entry["version_id"] == original.version_id
            assert entry["staging_labels"] == original.staging_labels


# ---------------------------------------------------------------------------
# Task 7.1: Unit tests for edge cases and error handling
# ---------------------------------------------------------------------------


class TestVersionMetadataUnitTests:
    """Unit tests for --versions flag, error handling, and security invariants.

    Validates: Requirements 1.1, 1.2, 2.5, 2.6, 6.3, 7.1, 7.2, 7.3
    """

    def test_versions_flag_in_help(self) -> None:
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--versions" in result.output

    def test_versions_flag_accepted(self) -> None:
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)
        patches = _pipeline_patches(session)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13], patches[14],
        ):
            result = runner.invoke(
                main, ["--secret", "test/secret", "--output", "json", "--versions"],
            )
        assert result.exit_code == 0, f"CLI failed: {result.output}"

    def test_versions_defaults_to_false(self) -> None:
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)
        patches = _pipeline_patches(session)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
            patches[14] as mock_lsv,
        ):
            result = runner.invoke(
                main, ["--secret", "test/secret", "--output", "json"]
            )
        assert result.exit_code == 0
        mock_lsv.assert_not_called()
        parsed = json.loads(result.output)
        assert parsed["versions"] == []

    def test_access_denied_returns_empty_with_warning(self) -> None:
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        error_response = {
            "Error": {"Code": "AccessDeniedException", "Message": "Access denied"}
        }
        mock_client.list_secret_version_ids.side_effect = (
            botocore.exceptions.ClientError(error_response, "ListSecretVersionIds")
        )
        versions, warnings = list_secret_versions(mock_session, _SECRET_ARN)
        assert versions == []
        assert len(warnings) == 1
        assert "access denied" in warnings[0].lower()

    def test_resource_not_found_returns_empty_with_warning(self) -> None:
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        error_response = {
            "Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}
        }
        mock_client.list_secret_version_ids.side_effect = (
            botocore.exceptions.ClientError(error_response, "ListSecretVersionIds")
        )
        versions, warnings = list_secret_versions(mock_session, _SECRET_ARN)
        assert versions == []
        assert len(warnings) == 1
        assert "not found" in warnings[0].lower()

    def test_versions_emits_progress_without_quiet(self) -> None:
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)
        version_data = [
            SecretVersionInfo(
                version_id="v1", staging_labels=["AWSCURRENT"],
                created_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
            )
        ]
        patches = list(_pipeline_patches(session))
        patches[14] = patch(
            "secrets_audit.cli.list_secret_versions",
            return_value=(version_data, []),
        )
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13], patches[14],
        ):
            result = runner.invoke(
                main, ["--secret", "test/secret", "--output", "json", "--versions"],
            )
        assert result.exit_code == 0, f"CLI failed: {result.output}"
        stderr_lower = result.stderr.lower()
        assert "version" in stderr_lower

    def test_versions_quiet_suppresses_progress(self) -> None:
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)
        version_data = [
            SecretVersionInfo(
                version_id="v1", staging_labels=["AWSCURRENT"],
                created_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
            )
        ]
        patches = list(_pipeline_patches(session))
        patches[14] = patch(
            "secrets_audit.cli.list_secret_versions",
            return_value=(version_data, []),
        )
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13], patches[14],
        ):
            result = runner.invoke(
                main, ["--secret", "test/secret", "--output", "json",
                       "--versions", "--quiet"],
            )
        assert result.exit_code == 0, f"CLI failed: {result.output}"
        assert result.stderr.strip() == ""

    def test_get_secret_value_never_called(self) -> None:
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_client.list_secret_version_ids.return_value = {
            "Versions": [
                {"VersionId": "v1", "VersionStages": ["AWSCURRENT"],
                 "CreatedDate": datetime(2025, 1, 1, tzinfo=timezone.utc)}
            ]
        }
        versions, warnings = list_secret_versions(mock_session, _SECRET_ARN)
        assert len(versions) == 1
        mock_client.get_secret_value.assert_not_called()
