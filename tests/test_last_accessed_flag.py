"""Unit and property-based tests for the --last-accessed flag (cloudtrail-opt-in)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from click.testing import CliRunner

from secrets_audit.cli import main
from secrets_audit.models import (
    AccessLevel,
    AuditReport,
    PrincipalAccess,
    PrincipalClassification,
    PrincipalType,
    ReportMetadata,
    SecretMetadata,
)
from secrets_audit.renderer import render
from secrets_audit.resolver import SimulationResult


# ---------------------------------------------------------------------------
# Helpers: pipeline patching (mirrors test_region_flag.py / test_master_profile.py)
# ---------------------------------------------------------------------------

_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf"  # nosec B105


def _mock_session() -> MagicMock:
    s = MagicMock()
    s.region_name = "us-east-1"
    return s


def _pipeline_patches(
    mock_session: MagicMock,
    principals: list[PrincipalAccess] | None = None,
    last_accessed_rv: dict | None = None,
):
    """Return a tuple of patch context managers for the full CLI pipeline."""
    return (
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
            return_value=SecretMetadata(name="test/secret", arn=_SECRET_ARN),
        ),
        patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
        patch("secrets_audit.cli.list_iam_roles", return_value=[]),
        patch("secrets_audit.cli.list_iam_users", return_value=[]),
        patch(
            "secrets_audit.cli.simulate_principal_access",
            return_value=SimulationResult(principals=principals or []),
        ),
        patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
        patch(
            "secrets_audit.cli.get_last_accessed",
            return_value=last_accessed_rv or {},
        ),
    )



# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Principal names: simple alphanumeric identifiers
_principal_names = st.from_regex(r"[a-zA-Z][a-zA-Z0-9_-]{0,19}", fullmatch=True)

# Last-accessed values: either a datetime or a status string
_last_accessed_values = st.one_of(
    st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2025, 12, 31),
        timezones=st.just(timezone.utc),
    ),
    st.sampled_from([
        "No recent access (>90 days)",
        "Unknown (CloudTrail unavailable)",
    ]),
)


def _build_principal(name: str) -> PrincipalAccess:
    """Build a minimal PrincipalAccess from a name."""
    return PrincipalAccess(
        principal_type=PrincipalType.IAM_ROLE,
        principal_arn=f"arn:aws:iam::123456789012:role/{name}",
        principal_name=name,
        access_level=AccessLevel.READ,
        classification=PrincipalClassification.PLAIN_IAM,
        policy_source="identity_policy",
    )


# ---------------------------------------------------------------------------
# Task 1.3: Unit tests for the --last-accessed flag
# ---------------------------------------------------------------------------


class TestLastAccessedFlagUnit:
    """Unit tests for the --last-accessed CLI flag.

    **Validates: Requirements 1.1, 1.2, 1.3**
    """

    def test_last_accessed_flag_accepted(self) -> None:
        """CLI accepts --last-accessed without error (Req 1.1)."""
        session = _mock_session()
        runner = CliRunner()
        with (
            patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name="test/secret", arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
        ):
            result = runner.invoke(main, ["--secret", "test/secret", "--last-accessed"])
        assert result.exit_code == 0, f"CLI failed: {result.output}"

    def test_last_accessed_default_false(self) -> None:
        """When --last-accessed is omitted, get_last_accessed is NOT called (Req 1.2)."""
        session = _mock_session()
        runner = CliRunner()
        with (
            patch("secrets_audit.cli.validate_secret_input", return_value="test/secret"),
            patch("secrets_audit.cli.validate_account_id", return_value=None),
            patch("secrets_audit.cli.validate_role_arn", return_value=None),
            patch("secrets_audit.cli.validate_region", return_value=None),
            patch("secrets_audit.cli.validate_profile_name", return_value=None),
            patch("secrets_audit.cli.create_prod_session", return_value=session),
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/tester"),
            patch("secrets_audit.cli.resolve_secret", return_value=SecretMetadata(name="test/secret", arn=_SECRET_ARN)),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.list_iam_roles", return_value=[]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _s, p: p),
            patch("secrets_audit.cli.get_last_accessed", return_value={}) as mock_get_la,
        ):
            result = runner.invoke(main, ["--secret", "test/secret"])
        assert result.exit_code == 0, f"CLI failed: {result.output}"
        mock_get_la.assert_not_called()

    def test_last_accessed_help_text(self) -> None:
        """--help output contains --last-accessed with CloudTrail and execution time (Req 1.3)."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--last-accessed" in result.output
        # Normalize whitespace (Click wraps long lines)
        help_normalised = " ".join(result.output.lower().split())
        assert "cloudtrail" in help_normalised
        assert "execution time" in help_normalised


# ---------------------------------------------------------------------------
# Task 2.1: Property 1 — Flag-off skips CloudTrail
# Feature: cloudtrail-opt-in, Property 1
# ---------------------------------------------------------------------------


class TestProperty1FlagOffSkipsCloudTrail:
    """Property 1: Flag-off skips CloudTrail and leaves all last_accessed as None.

    **Validates: Requirements 2.1, 2.2, 2.3**
    """

    @given(names=st.lists(_principal_names, min_size=1, max_size=5, unique=True))
    @settings(max_examples=100)
    def test_flag_off_skips_cloudtrail_and_nulls_last_accessed(
        self, names: list[str]
    ) -> None:
        """Without --last-accessed, get_last_accessed is not called and all
        principals have last_accessed=null in JSON output."""
        # Feature: cloudtrail-opt-in, Property 1
        principals = [_build_principal(n) for n in names]
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=principals)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7], patches[8], patches[9], \
             patches[10], patches[11], patches[12], patches[13] as mock_get_la:
            result = runner.invoke(
                main, ["--secret", "test/secret", "--output", "json"]
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        mock_get_la.assert_not_called()

        parsed = json.loads(result.output)
        for p in parsed["principals"]:
            assert p["last_accessed"] is None, (
                f"Expected null last_accessed for {p['principal_name']}, "
                f"got {p['last_accessed']!r}"
            )


# ---------------------------------------------------------------------------
# Task 2.2: Property 2 — Flag-on populates from CloudTrail
# Feature: cloudtrail-opt-in, Property 2
# ---------------------------------------------------------------------------


class TestProperty2FlagOnPopulatesFromCloudTrail:
    """Property 2: Flag-on populates last_accessed from CloudTrail results.

    **Validates: Requirements 3.1, 3.2**
    """

    @given(
        names=st.lists(_principal_names, min_size=1, max_size=5, unique=True),
        data=st.data(),
    )
    @settings(max_examples=100)
    def test_flag_on_populates_from_cloudtrail(
        self, names: list[str], data: st.DataObject
    ) -> None:
        """With --last-accessed, each principal's last_accessed matches the
        CloudTrail result map."""
        # Feature: cloudtrail-opt-in, Property 2
        principals = [_build_principal(n) for n in names]

        # Build a CloudTrail result map with a random value for each principal
        ct_map: dict[str, datetime | str] = {}
        expected: dict[str, str | None] = {}
        for p in principals:
            val = data.draw(_last_accessed_values)
            ct_map[p.principal_arn] = val
            if isinstance(val, datetime):
                expected[p.principal_name] = val.isoformat()
            else:
                expected[p.principal_name] = val

        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(
            session, principals=principals, last_accessed_rv=ct_map
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7], patches[8], patches[9], \
             patches[10], patches[11], patches[12], patches[13]:
            result = runner.invoke(
                main, ["--secret", "test/secret", "--last-accessed", "--output", "json"]
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        parsed = json.loads(result.output)
        for p_out in parsed["principals"]:
            name = p_out["principal_name"]
            assert p_out["last_accessed"] == expected[name], (
                f"Mismatch for {name}: expected {expected[name]!r}, "
                f"got {p_out['last_accessed']!r}"
            )


# ---------------------------------------------------------------------------
# Task 2.3: Property 3 — Renderer handles None last_accessed
# Feature: cloudtrail-opt-in, Property 3
# ---------------------------------------------------------------------------


class TestProperty3RendererNoneLastAccessed:
    """Property 3: Renderer displays None last_accessed correctly across all formats.

    **Validates: Requirements 4.1, 4.2, 4.3**
    """

    @given(names=st.lists(_principal_names, min_size=1, max_size=5, unique=True))
    @settings(max_examples=100)
    def test_renderer_none_last_accessed(self, names: list[str]) -> None:
        """For principals with last_accessed=None, table shows 'N/A',
        JSON shows null."""
        # Feature: cloudtrail-opt-in, Property 3
        principals = [_build_principal(n) for n in names]
        # Ensure all have last_accessed=None (the default)
        for p in principals:
            assert p.last_accessed is None

        report = AuditReport(
            metadata=ReportMetadata(
                secret_name="test/secret",
                secret_arn=_SECRET_ARN,
                generated_at="2025-01-01T00:00:00+00:00",
                generated_by="arn:aws:iam::123456789012:user/tester",
                tool_version="secrets-audit v1.0.0",
                region="us-east-1",
            ),
            principals=principals,
        )

        # Table: every principal row should contain "N/A" for last_accessed
        table_output = render(report, "table")
        # The table has a LAST ACCESSED column; each data row should show N/A
        data_lines = table_output.split("\n")
        # Find the separator line to know where data rows start
        sep_idx = next(
            i for i, line in enumerate(data_lines) if line.startswith("---")
        )
        for line in data_lines[sep_idx + 1 :]:
            if line.strip():
                assert "N/A" in line, f"Expected 'N/A' in table row: {line}"

        # JSON: every principal should have last_accessed == null
        json_output = render(report, "json")
        parsed_json = json.loads(json_output)
        for p_out in parsed_json["principals"]:
            assert p_out["last_accessed"] is None
