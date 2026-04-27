"""Property-based and unit tests for the region-flag feature."""

from __future__ import annotations

import json
import re

import click
import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from secrets_audit.validators import REGION_PATTERN, validate_region

# ---------------------------------------------------------------------------
# Hypothesis strategies for Property 1
# ---------------------------------------------------------------------------

# Strategy: generate strings that match REGION_PATTERN  ^[a-z]{2,4}(-[a-z]+-\d{1,2}){1}$
_valid_region_codes = st.builds(
    lambda prefix, geo, num: f"{prefix}-{geo}-{num}",
    prefix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=4),
    geo=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12),
    num=st.integers(min_value=0, max_value=99).map(str),
)


# ---------------------------------------------------------------------------
# Property 1: Region validation accepts valid and rejects invalid
# ---------------------------------------------------------------------------


class TestProperty1RegionValidation:
    """Property 1: Region validation accepts valid and rejects invalid.

    **Validates: Requirements 2.1, 2.2, 2.3**
    """

    @given(region=_valid_region_codes)
    @settings(max_examples=100)
    def test_validate_region_accepts_valid_codes(self, region: str) -> None:
        """Valid region codes matching REGION_PATTERN are returned unchanged."""
        # Feature: region-flag, Property 1
        assert REGION_PATTERN.match(region), f"Strategy bug: {region!r} doesn't match pattern"
        assert validate_region(region) == region

    @given(value=st.text())
    @settings(max_examples=100)
    def test_validate_region_rejects_invalid_strings(self, value: str) -> None:
        """Arbitrary strings that do NOT match REGION_PATTERN raise click.BadParameter."""
        # Feature: region-flag, Property 1
        assume(not REGION_PATTERN.match(value))
        with pytest.raises(click.BadParameter):
            validate_region(value)

    def test_validate_region_none_returns_none(self) -> None:
        """validate_region(None) returns None."""
        # Feature: region-flag, Property 1
        assert validate_region(None) is None


# ---------------------------------------------------------------------------
# Unit tests: Region validation edge cases
# ---------------------------------------------------------------------------


class TestRegionValidationEdgeCases:
    """Unit tests for region validation edge cases.

    **Validates: Requirements 2.1, 2.2, 2.3**
    """

    def test_none_returns_none(self) -> None:
        """validate_region(None) returns None."""
        assert validate_region(None) is None

    def test_valid_region_returned_unchanged(self) -> None:
        """validate_region('us-east-1') returns 'us-east-1'."""
        assert validate_region("us-east-1") == "us-east-1"

    def test_uppercase_rejected(self) -> None:
        """validate_region('US-EAST-1') raises click.BadParameter."""
        with pytest.raises(click.BadParameter):
            validate_region("US-EAST-1")

    def test_empty_string_rejected(self) -> None:
        """validate_region('') raises click.BadParameter."""
        with pytest.raises(click.BadParameter):
            validate_region("")

    def test_underscores_rejected(self) -> None:
        """validate_region('us_east_1') raises click.BadParameter."""
        with pytest.raises(click.BadParameter):
            validate_region("us_east_1")


# ---------------------------------------------------------------------------
# Property 2: Region propagation to production session
# ---------------------------------------------------------------------------

from secrets_audit.aws_clients import create_prod_session


class TestProperty2RegionPropagation:
    """Property 2: Region propagation to production session.

    **Validates: Requirements 1.3, 3.1**
    """

    @given(region=_valid_region_codes)
    @settings(max_examples=100)
    def test_region_propagates_to_session(self, region: str) -> None:
        """For any valid region code, create_prod_session(region=...) produces
        a session whose region_name equals the supplied value."""
        # Feature: region-flag, Property 2
        session = create_prod_session(region=region)
        assert session.region_name == region


# ---------------------------------------------------------------------------
# Unit tests: CLI --region wiring
# ---------------------------------------------------------------------------

from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from secrets_audit.cli import main
from secrets_audit.models import SecretMetadata
from secrets_audit.resolver import SimulationResult


def _patch_full_pipeline(**overrides):
    """Return a dict of patch context managers for the full CLI pipeline.

    Follows the same isolation pattern as TestCliOutputFile.test_output_file_writes_to_path
    in tests/test_cli.py — every pipeline function is patched so the CLI can
    run without real AWS credentials.

    Any key in *overrides* replaces the default return value for that patch target.
    """
    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"

    defaults = {
        "secrets_audit.cli.validate_secret_input": "test/secret",
        "secrets_audit.cli.validate_account_id": None,
        "secrets_audit.cli.validate_role_arn": None,
        "secrets_audit.cli.validate_region": overrides.pop("validate_region_rv", None),
        "secrets_audit.cli.create_prod_session": mock_session,
        "secrets_audit.cli.get_caller_identity": "arn:aws:iam::123456789012:user/tester",
        "secrets_audit.cli.resolve_secret": SecretMetadata(
            name="test/secret",
            arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
        ),
        "secrets_audit.cli.get_resource_policy_principals": [],
        "secrets_audit.cli.list_iam_roles": [],
        "secrets_audit.cli.list_iam_users": [],
        "secrets_audit.cli.simulate_principal_access": SimulationResult(principals=[]),
        "secrets_audit.cli.get_last_accessed": {},
    }
    defaults.update(overrides)
    return defaults, mock_session


class TestCliRegionWiring:
    """Unit tests for CLI --region option wiring.

    **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 3.3, 5.1, 5.2**
    """

    def test_help_contains_region_option(self) -> None:
        """--help output lists --region with description mentioning region and optional."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--region" in result.output
        # Description should mention "region" and indicate it's optional (via "Defaults")
        assert "region" in result.output.lower()
        assert "default" in result.output.lower()

    def test_no_region_passes_none_to_create_prod_session(self) -> None:
        """CLI invoked without --region calls create_prod_session(region=None)."""
        defaults, mock_session = _patch_full_pipeline()
        runner = CliRunner()

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=defaults["secrets_audit.cli.validate_secret_input"]),
            patch("secrets_audit.cli.validate_account_id", return_value=defaults["secrets_audit.cli.validate_account_id"]),
            patch("secrets_audit.cli.validate_role_arn", return_value=defaults["secrets_audit.cli.validate_role_arn"]),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=mock_session) as mock_create,
            patch("secrets_audit.cli.get_caller_identity", return_value=defaults["secrets_audit.cli.get_caller_identity"]),
            patch("secrets_audit.cli.resolve_secret", return_value=defaults["secrets_audit.cli.resolve_secret"]),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
        ):
            result = runner.invoke(main, ["--secret", "test/secret"])

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        mock_create.assert_called_once_with(region=None)

    def test_region_flag_passes_value_to_create_prod_session(self) -> None:
        """CLI invoked with --region us-west-2 calls create_prod_session(region='us-west-2')."""
        defaults, mock_session = _patch_full_pipeline()
        mock_session.region_name = "us-west-2"
        runner = CliRunner()

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=defaults["secrets_audit.cli.validate_secret_input"]),
            patch("secrets_audit.cli.validate_account_id", return_value=defaults["secrets_audit.cli.validate_account_id"]),
            patch("secrets_audit.cli.validate_role_arn", return_value=defaults["secrets_audit.cli.validate_role_arn"]),
            patch("secrets_audit.cli.validate_region", return_value="us-west-2"),
            patch("secrets_audit.cli.create_prod_session", return_value=mock_session) as mock_create,
            patch("secrets_audit.cli.get_caller_identity", return_value=defaults["secrets_audit.cli.get_caller_identity"]),
            patch("secrets_audit.cli.resolve_secret", return_value=defaults["secrets_audit.cli.resolve_secret"]),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
        ):
            result = runner.invoke(main, ["--secret", "test/secret", "--region", "us-west-2"])

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        mock_create.assert_called_once_with(region="us-west-2")

    def test_region_not_passed_to_cross_account_session(self) -> None:
        """CLI invoked with --region does NOT pass region to create_cross_account_session()."""
        defaults, mock_session = _patch_full_pipeline()
        mock_session.region_name = "eu-west-1"
        runner = CliRunner()

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=defaults["secrets_audit.cli.validate_secret_input"]),
            patch("secrets_audit.cli.validate_account_id", return_value="987654321098"),
            patch("secrets_audit.cli.validate_role_arn", return_value="arn:aws:iam::987654321098:role/cross-role"),
            patch("secrets_audit.cli.validate_region", return_value="eu-west-1"),
            patch("secrets_audit.cli.create_prod_session", return_value=mock_session),
            patch("secrets_audit.cli.get_caller_identity", return_value=defaults["secrets_audit.cli.get_caller_identity"]),
            patch("secrets_audit.cli.resolve_secret", return_value=defaults["secrets_audit.cli.resolve_secret"]),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch("secrets_audit.cli.create_cross_account_session", return_value=MagicMock()) as mock_cross,
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", "test/secret",
                    "--region", "eu-west-1",
                    "--master-account-id", "987654321098",
                    "--cross-account-role-arn", "arn:aws:iam::987654321098:role/cross-role",
                ],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        # create_cross_account_session should be called without a region kwarg
        mock_cross.assert_called_once()
        call_kwargs = mock_cross.call_args
        # The CLI passes (prod_session, role_arn) — region should NOT be in kwargs
        assert "region" not in (call_kwargs.kwargs or {}), (
            f"region should not be passed to create_cross_account_session, got kwargs: {call_kwargs.kwargs}"
        )

    def test_region_with_full_arn_secret_does_not_error(self) -> None:
        """CLI invoked with --region and a full ARN --secret does not error."""
        defaults, mock_session = _patch_full_pipeline()
        mock_session.region_name = "us-west-2"
        full_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf"
        runner = CliRunner()

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value=full_arn),
            patch("secrets_audit.cli.validate_account_id", return_value=defaults["secrets_audit.cli.validate_account_id"]),
            patch("secrets_audit.cli.validate_role_arn", return_value=defaults["secrets_audit.cli.validate_role_arn"]),
            patch("secrets_audit.cli.validate_region", return_value="us-west-2"),
            patch("secrets_audit.cli.create_prod_session", return_value=mock_session),
            patch("secrets_audit.cli.get_caller_identity", return_value=defaults["secrets_audit.cli.get_caller_identity"]),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name="test", arn=full_arn)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
        ):
            result = runner.invoke(
                main,
                ["--secret", full_arn, "--region", "us-west-2"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"


# ---------------------------------------------------------------------------
# Property 3: Region appears in rendered report metadata
# ---------------------------------------------------------------------------

from secrets_audit.models import AuditReport, ReportMetadata
from secrets_audit.renderer import render


class TestProperty3RegionInOutput:
    """Property 3: Region appears in rendered report metadata.

    **Validates: Requirements 4.1**
    """

    @given(region=_valid_region_codes)
    @settings(max_examples=100)
    def test_region_in_rendered_output(self, region: str) -> None:
        """For any valid AuditReport with ReportMetadata.region set to a
        non-None region string, render in each format (table, yaml, json)
        and assert the region string appears in the output."""
        # Feature: region-flag, Property 3
        report = AuditReport(
            metadata=ReportMetadata(
                secret_name="test/secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
                generated_at="2025-01-01T00:00:00+00:00",
                generated_by="arn:aws:iam::123456789012:user/tester",
                tool_version="secrets-audit v1.0.0",
                region=region,
            ),
        )
        for fmt in ("table", "json", "csv"):
            output = render(report, fmt)
            assert region in output, (
                f"Region {region!r} not found in {fmt} output:\n{output}"
            )


# ---------------------------------------------------------------------------
# Unit tests: Region display in output
# ---------------------------------------------------------------------------


class TestRegionDisplayInOutput:
    """Unit tests for region display in report output.

    **Validates: Requirements 4.1, 4.2**
    """

    def _make_report(self, region: str | None = None) -> AuditReport:
        """Helper to build a minimal AuditReport with the given region."""
        return AuditReport(
            metadata=ReportMetadata(
                secret_name="test/secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
                generated_at="2025-01-01T00:00:00+00:00",
                generated_by="arn:aws:iam::123456789012:user/tester",
                tool_version="secrets-audit v1.0.0",
                region=region,
            ),
        )

    def test_table_output_includes_region_line(self) -> None:
        """Table output includes a 'Region:' line with the region value."""
        report = self._make_report(region="us-west-2")
        output = render(report, "table")
        assert "Region: us-west-2" in output

    def test_json_output_includes_region_key(self) -> None:
        """JSON output includes 'region' key with the region value."""
        report = self._make_report(region="eu-central-1")
        output = render(report, "json")
        parsed = json.loads(output)
        assert parsed["region"] == "eu-central-1"

    def test_csv_output_includes_region_in_metadata(self) -> None:
        """CSV output includes region in metadata comment."""
        report = self._make_report(region="ap-southeast-1")
        output = render(report, "csv")
        assert "ap-southeast-1" in output

    def test_table_shows_default_when_region_is_none(self) -> None:
        """Table shows 'Region: (default)' when region is None."""
        report = self._make_report(region=None)
        output = render(report, "table")
        assert "Region: (default)" in output
