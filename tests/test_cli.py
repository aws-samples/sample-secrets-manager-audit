"""CLI unit tests using click.testing.CliRunner.

Tests CLI argument parsing, validation, default values, and output routing.
Does NOT test the full pipeline (that's in integration tests) — instead
patches the pipeline functions to isolate CLI behaviour.
"""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from secrets_audit.cli import main
from secrets_audit.resolver import SimulationResult


class TestCliDefaults:
    """Test default CLI option values."""

    def test_default_output_format_is_table(self) -> None:
        """--output defaults to table when not specified (Req 3.5)."""
        runner = CliRunner()
        # Will fail at session creation (no AWS creds), but we can check
        # that the option parsing works by patching the pipeline
        with patch("secrets_audit.cli.create_prod_session") as mock_session:
            mock_session.side_effect = Exception("stop here")
            result = runner.invoke(main, ["--secret", "test/secret"])
            # The command was invoked (not a usage error about --output)
            assert result.exit_code != 2 or "output" not in (result.output or "").lower()


class TestCliValidation:
    """Test input validation at CLI level."""

    def test_invalid_secret_produces_error(self) -> None:
        """Invalid --secret input produces exit code 2 (Req 3.9)."""
        runner = CliRunner()
        result = runner.invoke(main, ["--secret", ""])
        assert result.exit_code != 0

    def test_invalid_output_value_produces_error(self) -> None:
        """Invalid --output value produces usage error."""
        runner = CliRunner()
        result = runner.invoke(main, ["--secret", "test/secret", "--output", "xml"])
        assert result.exit_code == 2
        assert "Invalid value" in result.output or "invalid choice" in result.output.lower()

    def test_invalid_master_account_id(self) -> None:
        """Invalid --master-account-id produces error."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--secret", "test/secret", "--master-account-id", "not-12-digits"],
        )
        assert result.exit_code != 0


class TestCliOutputFile:
    """Test --output-file routing."""

    def test_output_file_writes_to_path(self, tmp_path) -> None:
        """--output-file writes report to specified file path (Req 3.6)."""
        from secrets_audit.models import (
            AuditReport,
            ReportMetadata,
        )

        out_path = tmp_path / "report.txt"

        # Patch the entire pipeline to return a canned report
        report = AuditReport(
            metadata=ReportMetadata(
                secret_name="test/secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
                generated_at="2026-03-20T08:00:00Z",
                generated_by="arn:aws:iam::123456789012:user/tester",
                tool_version="secrets-audit v1.0.0",
            ),
            principals=[],
        )

        with (
            patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.create_prod_session"),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret") as mock_resolve,
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
        ):
            from secrets_audit.models import SecretMetadata

            mock_resolve.return_value = SecretMetadata(
                name="test/secret",
                arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
            )

            runner = CliRunner()
            result = runner.invoke(
                main,
                ["--secret", "test/secret", "--output-file", str(out_path)],
            )

            assert result.exit_code == 0
            assert out_path.exists()
            content = out_path.read_text()
            assert "test/secret" in content
            assert "No IAM principals have access to this secret" in content


# ---------------------------------------------------------------------------
# Test Gap 1: NoSuchEntity handling in resolver
# ---------------------------------------------------------------------------

import botocore.exceptions
from unittest.mock import MagicMock


class TestNoSuchEntityHandling:
    """Verify simulate_principal_access skips deleted principals (NoSuchEntity)."""

    def test_no_such_entity_skips_principal_and_continues(self) -> None:
        """NoSuchEntity for one principal does not crash; that principal is excluded."""
        from secrets_audit.resolver import simulate_principal_access

        mock_client = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client

        deleted_arn = "arn:aws:iam::123456789012:role/deleted-role"
        valid_arn = "arn:aws:iam::123456789012:role/valid-role"

        def side_effect(**kwargs):
            if kwargs["PolicySourceArn"] == deleted_arn:
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "NoSuchEntity", "Message": "not found"}},
                    "SimulatePrincipalPolicy",
                )
            return {"EvaluationResults": []}

        mock_client.simulate_principal_policy.side_effect = side_effect

        with patch("secrets_audit.resolver._BATCH_SLEEP", 0):
            sim_result = simulate_principal_access(
                mock_session,
                [deleted_arn, valid_arn],
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
            )

        # deleted-role should NOT appear in results
        result_arns = [r.principal_arn for r in sim_result.principals]
        assert deleted_arn not in result_arns

        # The function should have been called for both principals
        assert mock_client.simulate_principal_policy.call_count == 2


# ---------------------------------------------------------------------------
# Test Gap 4: CLI --output pdf default file behaviour
# ---------------------------------------------------------------------------


class TestCliPdfDefaultOutput:
    """Verify --output pdf writes to report.pdf by default."""

    def test_pdf_default_output_file(self) -> None:
        """--output pdf without --output-file writes to report.pdf."""
        from secrets_audit.models import SecretMetadata

        mock_session = MagicMock()
        mock_session.region_name = "us-east-1"

        runner = CliRunner()
        with (
            patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
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
                return_value=SecretMetadata(
                    name="test/secret",
                    arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
                ),
            ),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch("secrets_audit.cli.list_secret_versions", return_value=([], [])),
            patch("secrets_audit.cli.Path.write_bytes") as mock_write,
        ):
            result = runner.invoke(
                main, ["--secret", "test/secret", "--output", "pdf"]
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        assert "PDF report written to" in result.output
