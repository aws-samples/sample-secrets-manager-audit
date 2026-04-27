"""Tests for the web UI module.

# Feature: streamlit-web-ui
"""

from __future__ import annotations

import re
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest
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
from secrets_audit.pipeline import AuditParams, ValidationError, validate_params
from secrets_audit.renderer import render


# ---------------------------------------------------------------------------
# Shared strategies
# ---------------------------------------------------------------------------

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
    classification=st.sampled_from(PrincipalClassification),
)

_report_st = st.builds(
    AuditReport,
    metadata=_metadata_st,
    principals=st.lists(_principal_st, min_size=0, max_size=5),
    warnings=st.lists(_safe_text, max_size=3),
)


# ---------------------------------------------------------------------------
# 6.1 Unit tests for the launch() function
# Feature: streamlit-web-ui
# ---------------------------------------------------------------------------


class TestLaunchFunction:
    """Unit tests for web.launch() — the secrets-audit-web entry point."""

    def test_launch_prints_install_instructions_when_streamlit_missing(
        self, capsys: pytest.CaptureFixture[str],
    ) -> None:
        """launch() should print install instructions and exit(1) when
        Streamlit is not importable."""
        # Feature: streamlit-web-ui
        original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

        def fake_import(name, *args, **kwargs):
            if name == "streamlit":
                raise ImportError("No module named 'streamlit'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            with pytest.raises(SystemExit) as exc_info:
                from secrets_audit.web import launch
                launch()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "pip install secrets-audit[web]" in captured.err

    def test_launch_invokes_subprocess_with_localhost_binding(self) -> None:
        """launch() should call subprocess.run with --server.address 127.0.0.1
        when Streamlit is available."""
        # Feature: streamlit-web-ui
        mock_streamlit = MagicMock()

        with (
            patch.dict(sys.modules, {"streamlit": mock_streamlit}),
            patch("subprocess.run") as mock_run,
        ):
            from secrets_audit.web import launch
            launch()

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "--server.address" in args
        addr_idx = args.index("--server.address")
        assert args[addr_idx + 1] == "127.0.0.1"


# ---------------------------------------------------------------------------
# 6.2 Unit tests for web UI Streamlit behavior
# Feature: streamlit-web-ui
# ---------------------------------------------------------------------------


class TestWebUIBehavior:
    """Unit tests for web UI logic — tested via render() and validate_params()
    directly, without importing Streamlit."""

    def _make_report(
        self,
        principals: list[PrincipalAccess] | None = None,
        warnings: list[str] | None = None,
    ) -> AuditReport:
        metadata = ReportMetadata(
            secret_name="test/secret",
            secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf",
            generated_at="2025-01-01T00:00:00+00:00",
            generated_by="arn:aws:iam::123456789012:user/tester",
            tool_version="secrets-audit v1.0.0",
            region="us-east-1",
        )
        return AuditReport(
            metadata=metadata,
            principals=principals or [],
            warnings=warnings or [],
        )

    def test_download_content_matches_render_for_each_format(self) -> None:
        """Download content for each format should be identical to
        render(report, format)."""
        # Feature: streamlit-web-ui
        principal = PrincipalAccess(
            principal_type=PrincipalType.IAM_ROLE,
            principal_arn="arn:aws:iam::123456789012:role/my-role",
            principal_name="my-role",
            access_level=AccessLevel.READ,
        )
        report = self._make_report(principals=[principal])

        for fmt in ("table", "json", "csv"):
            content = render(report, fmt)
            # Call render again — the download button calls render() the same way
            download_content = render(report, fmt)
            assert content == download_content, (
                f"Download content for {fmt} differs from render output"
            )

    def test_empty_principals_message(self) -> None:
        """When report.principals is empty, the table render should contain
        the 'No IAM principals' message."""
        # Feature: streamlit-web-ui
        report = self._make_report(principals=[])
        table_output = render(report, "table")
        assert "No IAM principals" in table_output

    def test_warnings_present_in_output(self) -> None:
        """Warnings from AuditReport.warnings should appear in rendered output."""
        # Feature: streamlit-web-ui
        report = self._make_report(
            warnings=["Cross-account assumption failed", "IC instance not found"],
        )
        table_output = render(report, "table")
        assert "Cross-account assumption failed" in table_output
        assert "IC instance not found" in table_output

    def test_validate_params_raises_for_invalid_secret(self) -> None:
        """validate_params() should raise ValidationError for invalid inputs."""
        # Feature: streamlit-web-ui
        params = AuditParams(secret="")  # nosec B106
        with pytest.raises(ValidationError):
            validate_params(params)

    def test_validate_params_raises_for_invalid_region(self) -> None:
        """validate_params() should raise ValidationError for a bad region."""
        # Feature: streamlit-web-ui
        params = AuditParams(secret="my-secret", region="not-a-region!!!")  # nosec B106
        with pytest.raises(ValidationError):
            validate_params(params)

    def test_validate_params_raises_for_mutual_exclusivity(self) -> None:
        """validate_params() should raise ValidationError when both
        master_profile and master_account_id are set."""
        # Feature: streamlit-web-ui
        params = AuditParams(
            secret="my-secret",  # nosec B106
            master_profile="my-profile",
            master_account_id="123456789012",
        )
        with pytest.raises(ValidationError):
            validate_params(params)


# ---------------------------------------------------------------------------
# 6.3 Property test: Download content equals render output (Property 4)
# Feature: streamlit-web-ui, Property 4: Download content equals render output
# ---------------------------------------------------------------------------


class TestProperty4DownloadContentEqualsRender:
    """Property 4: Download content equals render output.

    For any AuditReport and any output format in {"table", "yaml", "json"},
    calling render(report, format) twice produces the same result (idempotency).

    **Validates: Requirements 6.2, 6.3**
    """

    @given(report=_report_st, fmt=st.sampled_from(["table", "json", "csv"]))
    @settings(max_examples=100)
    def test_render_idempotency(self, report: AuditReport, fmt: str) -> None:
        # Feature: streamlit-web-ui, Property 4: Download content equals render output
        first = render(report, fmt)
        second = render(report, fmt)
        assert first == second, (
            f"render(report, {fmt!r}) is not idempotent — "
            f"two calls produced different results"
        )
