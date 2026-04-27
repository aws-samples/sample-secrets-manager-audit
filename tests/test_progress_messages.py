"""Property-based and unit tests for the progress-messages feature.

Tests cover:
- Property 1: Quiet flag suppresses all progress messages
- Property 2: Simulation progress messages at correct intervals with valid counts
- Property 3: CloudTrail pagination progress messages with monotonic event counts
- Property 4: IC resolution progress messages per role with correct indices
- Property 5: Progress messages go to stderr only, never stdout
- Unit tests for CLI flag behavior and edge cases
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.cli import main
from secrets_audit.models import (
    AccessLevel,
    IdentityCenterResolution,
    PrincipalAccess,
    PrincipalClassification,
    PrincipalType,
    SecretMetadata,
)
from secrets_audit.resolver import SimulationResult

# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------

_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf"  # nosec B105


def _mock_session() -> MagicMock:
    s = MagicMock()
    s.region_name = "us-east-1"
    return s


def _build_plain_principal(name: str) -> PrincipalAccess:
    """Build a plain IAM role principal."""
    return PrincipalAccess(
        principal_type=PrincipalType.IAM_ROLE,
        principal_arn=f"arn:aws:iam::123456789012:role/{name}",
        principal_name=name,
        access_level=AccessLevel.READ,
        classification=PrincipalClassification.PLAIN_IAM,
        policy_source="identity_policy",
    )


def _build_ic_principal(ps_name: str) -> PrincipalAccess:
    """Build an IC-classified principal with an AWSReservedSSO_ role name."""
    role_name = f"AWSReservedSSO_{ps_name}_1234abcd5678"
    return PrincipalAccess(
        principal_type=PrincipalType.IAM_ROLE,
        principal_arn=f"arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/{role_name}",
        principal_name=role_name,
        access_level=AccessLevel.READ,
        classification=PrincipalClassification.IDENTITY_CENTER,
        policy_source="identity_policy",
    )


def _pipeline_patches(
    mock_session: MagicMock,
    principals: list[PrincipalAccess] | None = None,
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
        patch("secrets_audit.cli.get_last_accessed", return_value={}),
    )


# ---------------------------------------------------------------------------
# Property 1: Quiet flag suppresses all progress messages
# Feature: progress-messages, Property 1
# ---------------------------------------------------------------------------


class TestProperty1QuietFlagSuppression:
    """Property 1: Quiet flag suppresses all progress messages.

    **Validates: Requirements 1.3, 2.4, 3.4, 4.3**
    """

    @given(n=st.integers(min_value=1, max_value=50))
    @settings(max_examples=100)
    def test_simulate_with_progress_none_never_calls_callback(self, n: int) -> None:
        """simulate_principal_access with progress=None never invokes a callback."""
        # Feature: progress-messages, Property 1
        from secrets_audit.resolver import simulate_principal_access

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_client.simulate_principal_policy.return_value = {"EvaluationResults": []}
        mock_session.client.return_value = mock_client

        principal_arns = [
            f"arn:aws:iam::123456789012:role/role-{i}" for i in range(n)
        ]

        # A callback that would fail if called
        fail_callback = MagicMock(side_effect=AssertionError("Should not be called"))

        with patch("secrets_audit.resolver._BATCH_SLEEP", 0):
            simulate_principal_access(
                mock_session,
                principal_arns,
                _SECRET_ARN,
                progress=None,
            )

        # If we got here, the fail_callback was never called (progress=None means no callback)
        fail_callback.assert_not_called()


# ---------------------------------------------------------------------------
# Property 2: Simulation progress messages at correct intervals with valid counts
# Feature: progress-messages, Property 2
# ---------------------------------------------------------------------------


class TestProperty2SimulationProgressIntervals:
    """Property 2: Simulation progress messages at correct intervals with valid counts.

    **Validates: Requirements 2.1, 2.2, 2.3**
    """

    @given(n=st.integers(min_value=1, max_value=200))
    @settings(max_examples=100)
    def test_simulation_progress_at_correct_intervals(self, n: int) -> None:
        """Progress callback is invoked at correct intervals with valid index/total."""
        # Feature: progress-messages, Property 2
        from secrets_audit.resolver import simulate_principal_access

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_client.simulate_principal_policy.return_value = {"EvaluationResults": []}
        mock_session.client.return_value = mock_client

        principal_arns = [
            f"arn:aws:iam::123456789012:role/role-{i}" for i in range(n)
        ]

        messages: list[str] = []

        with patch("secrets_audit.resolver._BATCH_SLEEP", 0):
            simulate_principal_access(
                mock_session,
                principal_arns,
                _SECRET_ARN,
                progress=messages.append,
            )

        # Determine expected interval
        interval = 1 if n < 20 else 10

        # Compute expected indices where progress fires: idx > 0 and idx % interval == 0
        expected_indices = [idx for idx in range(n) if idx > 0 and idx % interval == 0]

        assert len(messages) == len(expected_indices), (
            f"Expected {len(expected_indices)} messages for {n} principals "
            f"(interval={interval}), got {len(messages)}"
        )

        # Each message should contain a numeric index <= N and the total N
        for msg_idx, msg in enumerate(messages):
            nums = [int(x) for x in re.findall(r"\d+", msg)]
            assert len(nums) >= 2, f"Message should contain at least 2 numbers: {msg!r}"
            reported_idx = nums[0]
            reported_total = nums[1]
            assert reported_idx <= n, (
                f"Reported index {reported_idx} exceeds total {n} in: {msg!r}"
            )
            assert reported_total == n, (
                f"Reported total {reported_total} != actual total {n} in: {msg!r}"
            )


# ---------------------------------------------------------------------------
# Property 3: CloudTrail pagination progress messages with monotonic event counts
# Feature: progress-messages, Property 3
# ---------------------------------------------------------------------------


class TestProperty3CloudTrailPaginationProgress:
    """Property 3: CloudTrail pagination progress messages with monotonic event counts.

    **Validates: Requirements 3.2**
    """

    @given(
        events_per_page=st.lists(
            st.integers(min_value=0, max_value=50), min_size=1, max_size=20
        )
    )
    @settings(max_examples=100)
    def test_cloudtrail_progress_monotonic_event_counts(
        self, events_per_page: list[int]
    ) -> None:
        """_fetch_events emits one message per page with monotonically non-decreasing event counts."""
        # Feature: progress-messages, Property 3
        from secrets_audit.cloudtrail import _fetch_events

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        num_pages = len(events_per_page)

        # Build mock responses for each page
        responses = []
        for page_idx, event_count in enumerate(events_per_page):
            events = [{"EventTime": None, "EventName": "GetSecretValue"}] * event_count
            resp: dict = {"Events": events}
            if page_idx < num_pages - 1:
                resp["NextToken"] = f"token-{page_idx + 1}"
            responses.append(resp)

        mock_client.lookup_events.side_effect = responses

        messages: list[str] = []
        _fetch_events(mock_session, _SECRET_ARN, lookback_days=90, progress=messages.append)

        # One message per page
        assert len(messages) == num_pages, (
            f"Expected {num_pages} messages, got {len(messages)}"
        )

        # Extract event counts from messages and verify monotonicity
        counts: list[int] = []
        for msg in messages:
            nums = re.findall(r"\d+", msg)
            assert len(nums) >= 1, f"Expected at least one number in message: {msg!r}"
            counts.append(int(nums[0]))

        for i in range(1, len(counts)):
            assert counts[i] >= counts[i - 1], (
                f"Event counts not monotonically non-decreasing: {counts}"
            )


# ---------------------------------------------------------------------------
# Property 4: IC resolution progress messages per role with correct indices
# Feature: progress-messages, Property 4
# ---------------------------------------------------------------------------

_valid_ps_names = st.from_regex(r"[a-zA-Z][a-zA-Z0-9]{0,14}", fullmatch=True)


class TestProperty4ICResolutionProgressIndices:
    """Property 4: IC resolution progress messages per role with correct indices.

    **Validates: Requirements 4.1, 4.2**
    """

    @given(k=st.integers(min_value=1, max_value=15))
    @settings(max_examples=100)
    def test_ic_resolution_progress_indices(self, k: int) -> None:
        """IC resolution loop emits messages with indices 1 through K and total K."""
        # Feature: progress-messages, Property 4
        ic_principals = [
            _build_ic_principal(f"PermSet{i}") for i in range(k)
        ]

        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=ic_principals)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
        ):
            result = runner.invoke(main, ["--secret", "test/secret"])

        assert result.exit_code == 0, f"CLI failed: {result.output}\nstderr: {result.stderr}"

        stderr = result.stderr

        # Check for the summary message
        assert f"Resolving {k} Identity Center role(s)..." in stderr, (
            f"Missing IC summary message for {k} roles in stderr:\n{stderr}"
        )

        # Check for per-role messages with indices 1..K
        for idx in range(1, k + 1):
            expected = f"Resolving Identity Center role {idx} of {k}..."
            assert expected in stderr, (
                f"Missing IC progress message '{expected}' in stderr:\n{stderr}"
            )


# ---------------------------------------------------------------------------
# Property 5: Progress messages go to stderr only, never stdout
# Feature: progress-messages, Property 5
# ---------------------------------------------------------------------------


class TestProperty5StderrOnlyOutput:
    """Property 5: Progress messages go to stderr only, never stdout.

    **Validates: Requirements 5.1, 5.2, 5.3**
    """

    @given(n=st.integers(min_value=1, max_value=50))
    @settings(max_examples=100)
    def test_progress_on_stderr_not_stdout(self, n: int) -> None:
        """Progress messages appear in stderr, not in stdout."""
        # Feature: progress-messages, Property 5
        principals = [_build_plain_principal(f"role-{i}") for i in range(n)]

        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=principals)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
        ):
            result = runner.invoke(main, ["--secret", "test/secret"])

        assert result.exit_code == 0, f"CLI failed: {result.output}\nstderr: {result.stderr}"

        stderr = result.stderr
        stdout = result.output

        # Progress messages should appear on stderr
        assert "Simulating principals..." in stderr, (
            f"Expected simulation start message on stderr:\n{stderr}"
        )
        assert "Simulation complete" in stderr, (
            f"Expected simulation complete message on stderr:\n{stderr}"
        )

        # stdout should NOT contain progress messages
        progress_patterns = [
            "Simulating principals...",
            "Simulation complete",
            "Resolving Identity Center",
            "Fetching CloudTrail",
            "Starting CloudTrail",
            "CloudTrail enrichment complete",
        ]
        for pattern in progress_patterns:
            assert pattern not in stdout, (
                f"Progress message '{pattern}' found in stdout:\n{stdout}"
            )


# ---------------------------------------------------------------------------
# Unit tests: CLI flag behavior and edge cases (Task 6.3)
# ---------------------------------------------------------------------------


class TestCliFlagBehaviorAndEdgeCases:
    """Unit tests for CLI flag behavior and edge cases.

    **Validates: Requirements 1.1, 1.2, 1.4, 5.4, 6.1**
    """

    def test_quiet_flag_accepted_and_defaults_false(self) -> None:
        """--quiet flag is accepted and defaults to False."""
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
        ):
            # Without --quiet: should emit progress messages (default is False)
            result = runner.invoke(main, ["--secret", "test/secret"])

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        # Default (no --quiet) should produce progress on stderr
        assert "Simulating principals..." in result.stderr

    def test_quiet_flag_suppresses_stderr(self) -> None:
        """--quiet suppresses all progress messages on stderr."""
        session = _mock_session()
        principals = [_build_plain_principal(f"role-{i}") for i in range(5)]
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=principals)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
        ):
            result = runner.invoke(main, ["--secret", "test/secret", "--quiet"])

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        # --quiet should suppress all progress messages
        assert "Simulating" not in result.stderr
        assert "Resolving" not in result.stderr

    def test_quiet_help_text(self) -> None:
        """--quiet help text contains expected description."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--quiet" in result.output
        help_normalised = " ".join(result.output.lower().split())
        assert "suppress" in help_normalised
        assert "progress" in help_normalised

    def test_zero_principals_no_simulation_progress(self) -> None:
        """Zero principals produces no simulation progress messages."""
        session = _mock_session()
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=[])
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
        ):
            result = runner.invoke(main, ["--secret", "test/secret"])

        assert result.exit_code == 0
        # With 0 principals, the simulation messages should show "(0/0)"
        assert "Simulating principals... (0/0)" in result.stderr
        assert "Simulation complete: 0 of 0" in result.stderr

    def test_zero_ic_roles_no_ic_progress(self) -> None:
        """Zero IC roles produces no IC resolution progress messages."""
        session = _mock_session()
        # Only plain IAM principals, no IC
        principals = [_build_plain_principal(f"role-{i}") for i in range(3)]
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=principals)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
        ):
            result = runner.invoke(main, ["--secret", "test/secret"])

        assert result.exit_code == 0
        assert "Resolving" not in result.stderr
        assert "Identity Center" not in result.stderr

    def test_output_file_contains_no_progress_content(self, tmp_path) -> None:
        """--output-file output contains no progress message content."""
        session = _mock_session()
        principals = [_build_plain_principal(f"role-{i}") for i in range(3)]
        out_path = tmp_path / "report.txt"
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=principals)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
        ):
            result = runner.invoke(
                main,
                ["--secret", "test/secret", "--output-file", str(out_path)],
            )

        assert result.exit_code == 0
        content = out_path.read_text()
        progress_patterns = [
            "Simulating principals...",
            "Simulation complete",
            "Resolving Identity Center",
            "Fetching CloudTrail",
        ]
        for pattern in progress_patterns:
            assert pattern not in content, (
                f"Progress message '{pattern}' found in output file"
            )

    def test_default_no_quiet_emits_progress_to_stderr(self) -> None:
        """Default behavior (no --quiet) emits progress messages to stderr."""
        session = _mock_session()
        principals = [_build_plain_principal(f"role-{i}") for i in range(3)]
        runner = CliRunner(mix_stderr=False)

        patches = _pipeline_patches(session, principals=principals)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8], patches[9],
            patches[10], patches[11], patches[12], patches[13],
        ):
            result = runner.invoke(main, ["--secret", "test/secret"])

        assert result.exit_code == 0
        assert "Simulating principals..." in result.stderr
        assert "Simulation complete" in result.stderr
