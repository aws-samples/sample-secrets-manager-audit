# Feature: simulator-limitation-warning
"""Property-based tests for simulator limitation warning feature.

Tests verify that the simulation loop correctly classifies principals as
"fully denied" based on MatchedStatements emptiness, and preserves existing
behavior for principals with allowed actions.

**Security invariant**: these tests never call ``GetSecretValue``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.resolver import SimulationResult, simulate_principal_access


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_SM_ACTIONS = st.sampled_from([
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:DeleteSecret",
    "secretsmanager:CreateSecret",
    "secretsmanager:DescribeSecret",
])

_PRINCIPAL_ARN = st.just("arn:aws:iam::123456789012:role/TestRole")

_SECRET_ARN = st.just(
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf"
)


# Strategy: generate 1-6 EvaluationResults where ALL have implicitDeny + empty MatchedStatements
_FULLY_DENIED_EVAL_RESULTS = st.lists(
    st.fixed_dictionaries({
        "EvalActionName": _SM_ACTIONS,
        "EvalDecision": st.just("implicitDeny"),
        "MatchedStatements": st.just([]),
    }),
    min_size=1,
    max_size=6,
)

# Strategy for a single MatchedStatement entry (non-empty)
_MATCHED_STATEMENT = st.fixed_dictionaries({
    "SourcePolicyId": st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8),
    "SourcePolicyType": st.just("IAM Policy"),
})

# Strategy: generate disqualifying eval results — at least one entry breaks
# the fully-denied condition (allowed, explicitDeny, or non-empty MatchedStatements)
_DISQUALIFYING_ENTRY = st.one_of(
    # Case 1: allowed decision
    st.fixed_dictionaries({
        "EvalActionName": _SM_ACTIONS,
        "EvalDecision": st.just("allowed"),
        "MatchedStatements": st.lists(_MATCHED_STATEMENT, min_size=1, max_size=2),
    }),
    # Case 2: explicitDeny decision
    st.fixed_dictionaries({
        "EvalActionName": _SM_ACTIONS,
        "EvalDecision": st.just("explicitDeny"),
        "MatchedStatements": st.lists(_MATCHED_STATEMENT, min_size=1, max_size=2),
    }),
    # Case 3: implicitDeny but non-empty MatchedStatements
    st.fixed_dictionaries({
        "EvalActionName": _SM_ACTIONS,
        "EvalDecision": st.just("implicitDeny"),
        "MatchedStatements": st.lists(_MATCHED_STATEMENT, min_size=1, max_size=2),
    }),
)

# At least one disqualifying entry, optionally mixed with benign entries
_NOT_FULLY_DENIED_EVAL_RESULTS = st.tuples(
    _DISQUALIFYING_ENTRY,
    st.lists(
        st.one_of(
            _DISQUALIFYING_ENTRY,
            st.fixed_dictionaries({
                "EvalActionName": _SM_ACTIONS,
                "EvalDecision": st.just("implicitDeny"),
                "MatchedStatements": st.just([]),
            }),
        ),
        min_size=0,
        max_size=5,
    ),
).map(lambda t: [t[0]] + t[1])

# Strategy for allowed eval results (at least one allowed action)
_ALLOWED_EVAL_ENTRY = st.one_of(
    # Top-level allowed
    st.fixed_dictionaries({
        "EvalActionName": _SM_ACTIONS,
        "EvalDecision": st.just("allowed"),
        "MatchedStatements": st.lists(_MATCHED_STATEMENT, min_size=0, max_size=2),
    }),
    # Allowed via ResourceSpecificResults
    st.fixed_dictionaries({
        "EvalActionName": _SM_ACTIONS,
        "EvalDecision": st.just("implicitDeny"),
        "MatchedStatements": st.just([]),
        "ResourceSpecificResults": st.just([{
            "EvalResourceName": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf",
            "EvalResourceDecision": "allowed",
        }]),
    }),
)

_AT_LEAST_ONE_ALLOWED_EVAL_RESULTS = st.tuples(
    _ALLOWED_EVAL_ENTRY,
    st.lists(
        st.one_of(
            _ALLOWED_EVAL_ENTRY,
            st.fixed_dictionaries({
                "EvalActionName": _SM_ACTIONS,
                "EvalDecision": st.just("implicitDeny"),
                "MatchedStatements": st.just([]),
            }),
        ),
        min_size=0,
        max_size=5,
    ),
).map(lambda t: [t[0]] + t[1])


# ---------------------------------------------------------------------------
# Property 1: Fully-denied positive classification
# ---------------------------------------------------------------------------


class TestProperty1FullyDeniedPositive:
    """Property 1: Fully-denied positive classification.

    For any principal where ALL actions have implicitDeny + empty
    MatchedStatements and no allowed ResourceSpecificResults, the
    principal's ARN SHALL appear in SimulationResult.fully_denied_arns.

    **Validates: Requirements 1.1, 6.1**
    """

    @given(eval_results=_FULLY_DENIED_EVAL_RESULTS)
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_all_implicit_deny_empty_matched_is_fully_denied(
        self,
        eval_results: list[dict],
    ) -> None:
        """A principal with all implicitDeny + empty MatchedStatements
        MUST appear in fully_denied_arns.

        **Validates: Requirements 1.1, 6.1**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        principal_arn = "arn:aws:iam::123456789012:role/FullyDeniedRole"
        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": eval_results,
        }

        result = simulate_principal_access(
            mock_session,
            [principal_arn],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf",
        )

        assert principal_arn in result.fully_denied_arns, (
            f"Principal {principal_arn} should be in fully_denied_arns when all "
            f"actions have implicitDeny + empty MatchedStatements. "
            f"Got fully_denied_arns={result.fully_denied_arns}"
        )
        # Should NOT appear in principals (no allowed actions)
        assert all(
            p.principal_arn != principal_arn for p in result.principals
        ), "Fully denied principal should not appear in principals list"


# ---------------------------------------------------------------------------
# Property 2: Fully-denied negative classification
# ---------------------------------------------------------------------------


class TestProperty2FullyDeniedNegative:
    """Property 2: Fully-denied negative classification.

    For any principal where at least one action has allowed, explicitDeny,
    or non-empty MatchedStatements, the principal's ARN SHALL NOT appear
    in SimulationResult.fully_denied_arns.

    **Validates: Requirements 1.2, 1.3, 1.4**
    """

    @given(eval_results=_NOT_FULLY_DENIED_EVAL_RESULTS)
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_disqualifying_condition_not_fully_denied(
        self,
        eval_results: list[dict],
    ) -> None:
        """A principal with at least one disqualifying condition (allowed,
        explicitDeny, or non-empty MatchedStatements) MUST NOT appear in
        fully_denied_arns.

        **Validates: Requirements 1.2, 1.3, 1.4**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        principal_arn = "arn:aws:iam::123456789012:role/NotFullyDeniedRole"
        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": eval_results,
        }

        result = simulate_principal_access(
            mock_session,
            [principal_arn],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf",
        )

        assert principal_arn not in result.fully_denied_arns, (
            f"Principal {principal_arn} should NOT be in fully_denied_arns when "
            f"at least one action has allowed/explicitDeny/non-empty MatchedStatements. "
            f"EvaluationResults={eval_results}"
        )


# ---------------------------------------------------------------------------
# Property 5: Preservation of existing simulation behavior
# ---------------------------------------------------------------------------


class TestProperty5PreservationBehavior:
    """Property 5: Preservation of existing simulation behavior.

    For any principal where at least one action has EvalDecision == "allowed"
    (top-level or via ResourceSpecificResults), the principal SHALL appear
    in SimulationResult.principals with the correct allowed_actions.

    **Validates: Requirements 6.3**
    """

    @given(eval_results=_AT_LEAST_ONE_ALLOWED_EVAL_RESULTS)
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_allowed_principal_in_results(
        self,
        eval_results: list[dict],
    ) -> None:
        """A principal with at least one allowed action MUST appear in
        SimulationResult.principals with the correct allowed_actions.

        **Validates: Requirements 6.3**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        principal_arn = "arn:aws:iam::123456789012:role/AllowedRole"
        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": eval_results,
        }

        result = simulate_principal_access(
            mock_session,
            [principal_arn],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf",
        )

        # Compute expected allowed actions
        expected_allowed: list[str] = []
        for er in eval_results:
            action = er["EvalActionName"]
            if er.get("EvalDecision") == "allowed":
                if action not in expected_allowed:
                    expected_allowed.append(action)
                continue
            for rsr in er.get("ResourceSpecificResults", []):
                if rsr.get("EvalResourceDecision") == "allowed":
                    if action not in expected_allowed:
                        expected_allowed.append(action)
                    break

        assert len(result.principals) == 1, (
            f"Expected 1 principal with access, got {len(result.principals)}. "
            f"EvaluationResults={eval_results}"
        )
        assert result.principals[0].principal_arn == principal_arn
        assert set(result.principals[0].allowed_actions) == set(expected_allowed), (
            f"Expected allowed_actions={expected_allowed}, "
            f"got {result.principals[0].allowed_actions}"
        )
        # Should NOT be in fully_denied_arns
        assert principal_arn not in result.fully_denied_arns, (
            "Principal with allowed actions should not be in fully_denied_arns"
        )


# ---------------------------------------------------------------------------
# Imports for inspect_context_keys tests
# ---------------------------------------------------------------------------

import botocore.exceptions
from secrets_audit.resolver import inspect_context_keys


# ---------------------------------------------------------------------------
# Strategies for context key tests
# ---------------------------------------------------------------------------

# Non-matching context key: any key that does NOT start with secretsmanager:ResourceTag/
_NON_MATCHING_KEY = st.one_of(
    st.just("aws:username"),
    st.just("aws:ResourceTag/env"),
    st.just("secretsmanager:SecretId"),
    st.just("aws:PrincipalOrgID"),
    st.just("ec2:ResourceTag/team"),
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz:/-_",
        min_size=1,
        max_size=40,
    ).filter(lambda k: not k.startswith("secretsmanager:ResourceTag/")),
)

# Matching context key: starts with secretsmanager:ResourceTag/
_MATCHING_KEY = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    min_size=1,
    max_size=30,
).map(lambda tag: f"secretsmanager:ResourceTag/{tag}")

# IAM ARN strategies for context key tests
_CONTEXT_KEY_PRINCIPAL_ARN = st.one_of(
    st.just("arn:aws:iam::123456789012:role/TestRole"),
    st.just("arn:aws:iam::123456789012:user/TestUser"),
    st.just("arn:aws:iam::123456789012:role/my-app/ServiceRole"),
)


# ---------------------------------------------------------------------------
# Property 3: Context key matching produces warning
# ---------------------------------------------------------------------------


class TestProperty3ContextKeyMatchingWarning:
    """Property 3: Context key matching produces warning.

    For any principal ARN and any list of context key names that includes
    at least one key starting with ``secretsmanager:ResourceTag/``, the
    ``inspect_context_keys`` function SHALL return a warning containing
    the principal's friendly name and ``secretsmanager:ResourceTag``.

    **Validates: Requirements 2.3, 3.1**
    """

    @given(
        principal_arn=_CONTEXT_KEY_PRINCIPAL_ARN,
        matching_key=_MATCHING_KEY,
        other_keys=st.lists(_NON_MATCHING_KEY, min_size=0, max_size=5),
    )
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_matching_key_produces_warning(
        self,
        principal_arn: str,
        matching_key: str,
        other_keys: list[str],
    ) -> None:
        """A principal whose policies reference secretsmanager:ResourceTag/
        keys MUST produce a warning containing the principal name.

        **Validates: Requirements 2.3, 3.1**
        """
        all_keys = other_keys + [matching_key]

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_client.get_context_keys_for_principal_policy.return_value = {
            "ContextKeyNames": all_keys,
        }

        flagged, inspection = inspect_context_keys(
            mock_session, [principal_arn],
        )

        friendly_name = principal_arn.rsplit("/", 1)[-1]
        assert len(flagged) == 1, (
            f"Expected 1 flagged warning, got {len(flagged)}. Keys={all_keys}"
        )
        assert friendly_name in flagged[0], (
            f"Warning should contain principal name {friendly_name!r}, got: {flagged[0]}"
        )
        assert "secretsmanager:ResourceTag" in flagged[0], (
            f"Warning should mention secretsmanager:ResourceTag, got: {flagged[0]}"
        )
        assert len(inspection) == 0, "No inspection warnings expected"


# ---------------------------------------------------------------------------
# Property 4: No matching context keys produces no warning
# ---------------------------------------------------------------------------


class TestProperty4NoMatchingKeysNoWarning:
    """Property 4: No matching context keys produces no warning.

    For any principal ARN and any list of context key names that does NOT
    include any key starting with ``secretsmanager:ResourceTag/``, the
    ``inspect_context_keys`` function SHALL NOT return any warning for
    that principal.

    **Validates: Requirements 2.4, 3.3**
    """

    @given(
        principal_arn=_CONTEXT_KEY_PRINCIPAL_ARN,
        keys=st.lists(_NON_MATCHING_KEY, min_size=0, max_size=10),
    )
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_no_matching_key_no_warning(
        self,
        principal_arn: str,
        keys: list[str],
    ) -> None:
        """A principal whose policies do NOT reference secretsmanager:ResourceTag/
        keys MUST NOT produce any flagged warning.

        **Validates: Requirements 2.4, 3.3**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_client.get_context_keys_for_principal_policy.return_value = {
            "ContextKeyNames": keys,
        }

        flagged, inspection = inspect_context_keys(
            mock_session, [principal_arn],
        )

        assert len(flagged) == 0, (
            f"Expected 0 flagged warnings for keys without secretsmanager:ResourceTag/, "
            f"got {len(flagged)}: {flagged}. Keys={keys}"
        )
        assert len(inspection) == 0, "No inspection warnings expected"


# ---------------------------------------------------------------------------
# Unit tests: error handling in inspect_context_keys
# ---------------------------------------------------------------------------


class TestInspectContextKeysErrorHandling:
    """Unit tests for error handling in inspect_context_keys().

    **Validates: Requirements 5.1, 5.2, 5.3, 2.5**
    """

    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_access_denied_skips_principal_and_continues(self) -> None:
        """AccessDeniedException skips the principal and continues to the next.

        **Validates: Requirement 5.1**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        arn_denied = "arn:aws:iam::123456789012:role/DeniedRole"
        arn_ok = "arn:aws:iam::123456789012:role/OkRole"

        error_response = {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}}
        access_denied_exc = botocore.exceptions.ClientError(error_response, "GetContextKeysForPrincipalPolicy")

        mock_client.get_context_keys_for_principal_policy.side_effect = [
            access_denied_exc,
            {"ContextKeyNames": ["secretsmanager:ResourceTag/env"]},
        ]

        flagged, inspection = inspect_context_keys(
            mock_session, [arn_denied, arn_ok],
        )

        assert len(flagged) == 1, "Second principal should still be processed"
        assert "OkRole" in flagged[0]
        assert len(inspection) == 0

    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_no_such_entity_skips_principal_and_continues(self) -> None:
        """NoSuchEntity skips the principal and continues to the next.

        **Validates: Requirement 5.2**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        arn_gone = "arn:aws:iam::123456789012:role/DeletedRole"
        arn_ok = "arn:aws:iam::123456789012:role/OkRole"

        error_response = {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}}
        no_such_exc = botocore.exceptions.ClientError(error_response, "GetContextKeysForPrincipalPolicy")

        mock_client.get_context_keys_for_principal_policy.side_effect = [
            no_such_exc,
            {"ContextKeyNames": ["secretsmanager:ResourceTag/team"]},
        ]

        flagged, inspection = inspect_context_keys(
            mock_session, [arn_gone, arn_ok],
        )

        assert len(flagged) == 1, "Second principal should still be processed"
        assert "OkRole" in flagged[0]
        assert len(inspection) == 0

    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_expired_token_adds_warning_and_stops_loop(self) -> None:
        """Expired token adds an inspection warning and stops processing.

        **Validates: Requirement 5.3**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        arn1 = "arn:aws:iam::123456789012:role/Role1"
        arn2 = "arn:aws:iam::123456789012:role/Role2"
        arn3 = "arn:aws:iam::123456789012:role/Role3"

        error_response = {"Error": {"Code": "ExpiredTokenException", "Message": "Token expired"}}
        expired_exc = botocore.exceptions.ClientError(error_response, "GetContextKeysForPrincipalPolicy")

        mock_client.get_context_keys_for_principal_policy.side_effect = [
            {"ContextKeyNames": ["secretsmanager:ResourceTag/env"]},
            expired_exc,
            # arn3 should never be reached
        ]

        flagged, inspection = inspect_context_keys(
            mock_session, [arn1, arn2, arn3],
        )

        # arn1 should produce a warning
        assert len(flagged) == 1
        assert "Role1" in flagged[0]

        # Inspection warning about incomplete inspection
        assert len(inspection) == 1
        assert "expired" in inspection[0].lower()

        # arn3 should NOT have been called
        assert mock_client.get_context_keys_for_principal_policy.call_count == 2

    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_get_secret_value_never_called(self) -> None:
        """Security invariant: GetSecretValue is never called.

        **Validates: Requirement 2.5**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.get_context_keys_for_principal_policy.return_value = {
            "ContextKeyNames": ["secretsmanager:ResourceTag/env"],
        }

        inspect_context_keys(
            mock_session,
            ["arn:aws:iam::123456789012:role/TestRole"],
        )

        # Verify GetSecretValue was never called
        mock_client.get_secret_value.assert_not_called()


# ---------------------------------------------------------------------------
# Unit tests: CLI pipeline wiring for inspect_context_keys
# ---------------------------------------------------------------------------

from click.testing import CliRunner
from secrets_audit.cli import main
from secrets_audit.models import (
    AccessLevel,
    PrincipalAccess,
    PrincipalType,
    SecretMetadata,
)
from secrets_audit.resolver import SimulationResult


class TestPipelineWiringInspectContextKeys:
    """Unit tests for wiring inspect_context_keys into the CLI pipeline.

    Verifies that inspect_context_keys is called only when appropriate
    (fully-denied principals exist and simulation was not truncated),
    and that resulting warnings appear in the final report.

    **Validates: Requirements 2.1, 2.2, 3.1, 3.2, 4.1, 4.2, 4.3, 4.4**
    """

    def _run_pipeline(
        self,
        sim_result: SimulationResult,
        inspect_return: tuple[list[str], list[str]] = ([], []),
    ) -> tuple[MagicMock, str, MagicMock]:
        """Helper: run the CLI pipeline with mocked dependencies.

        Returns (mock_inspect_context_keys, cli_output, mock_render).
        """
        runner = CliRunner()

        secret_meta = SecretMetadata(
            name="test-secret",
            arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf",
            tags={},
        )

        with (
            patch("secrets_audit.cli.create_prod_session") as mock_session_factory,
            patch("secrets_audit.cli.get_caller_identity", return_value="arn:aws:iam::123456789012:user/operator"),
            patch("secrets_audit.cli.resolve_secret", return_value=secret_meta),
            patch("secrets_audit.cli.list_iam_roles", return_value=["arn:aws:iam::123456789012:role/TestRole"]),
            patch("secrets_audit.cli.list_iam_users", return_value=[]),
            patch("secrets_audit.cli.simulate_principal_access", return_value=sim_result),
            patch("secrets_audit.cli.get_resource_policy_principals", return_value=[]),
            patch("secrets_audit.cli.inspect_context_keys", return_value=inspect_return) as mock_inspect,
            patch("secrets_audit.cli.classify_principal", side_effect=lambda _sess, p: p),
            patch("secrets_audit.cli.render", return_value="rendered-output") as mock_render,
        ):
            mock_session = MagicMock()
            mock_session.region_name = "us-east-1"
            mock_session_factory.return_value = mock_session

            result = runner.invoke(main, ["--secret", "test-secret", "--quiet"])

            return mock_inspect, result.output, mock_render

    def test_inspect_called_for_fully_denied_principals(self) -> None:
        """inspect_context_keys is called when fully_denied_arns is non-empty
        and truncated is False.

        **Validates: Requirements 2.1, 4.3**
        """
        denied_arn = "arn:aws:iam::123456789012:role/DeniedRole"
        sim_result = SimulationResult(
            principals=[],
            truncated=False,
            evaluated_count=1,
            total_count=1,
            fully_denied_arns=[denied_arn],
        )

        mock_inspect, output, _ = self._run_pipeline(sim_result)

        mock_inspect.assert_called_once()
        call_args = mock_inspect.call_args
        assert call_args[0][1] == [denied_arn], (
            "inspect_context_keys should be called with the fully_denied_arns list"
        )

    def test_inspect_skipped_when_truncated(self) -> None:
        """inspect_context_keys is NOT called when sim_result.truncated is True.

        **Validates: Requirement 4.4**
        """
        sim_result = SimulationResult(
            principals=[],
            truncated=True,
            evaluated_count=5,
            total_count=10,
            fully_denied_arns=["arn:aws:iam::123456789012:role/DeniedRole"],
        )

        mock_inspect, output, _ = self._run_pipeline(sim_result)

        mock_inspect.assert_not_called()

    def test_inspect_skipped_when_no_fully_denied(self) -> None:
        """inspect_context_keys is NOT called when fully_denied_arns is empty.

        **Validates: Requirements 4.1, 4.2**
        """
        sim_result = SimulationResult(
            principals=[
                PrincipalAccess(
                    principal_type=PrincipalType.IAM_ROLE,
                    principal_arn="arn:aws:iam::123456789012:role/AllowedRole",
                    principal_name="AllowedRole",
                    access_level=AccessLevel.READ,
                    allowed_actions=["secretsmanager:GetSecretValue"],
                ),
            ],
            truncated=False,
            evaluated_count=1,
            total_count=1,
            fully_denied_arns=[],
        )

        mock_inspect, output, _ = self._run_pipeline(sim_result)

        mock_inspect.assert_not_called()

    def test_warnings_appear_in_final_report(self) -> None:
        """Limitation warnings from inspect_context_keys appear in AuditReport.warnings.

        **Validates: Requirements 3.1, 3.2**
        """
        denied_arn = "arn:aws:iam::123456789012:role/TagBasedRole"
        sim_result = SimulationResult(
            principals=[],
            truncated=False,
            evaluated_count=1,
            total_count=1,
            fully_denied_arns=[denied_arn],
        )

        flagged_warning = (
            "Principal TagBasedRole has policies using secretsmanager:ResourceTag "
            "conditions which the IAM Policy Simulator cannot evaluate. "
            "This principal may have access that is not reflected in this report."
        )
        inspect_return = ([flagged_warning], [])

        mock_inspect, output, mock_render = self._run_pipeline(
            sim_result, inspect_return=inspect_return
        )

        mock_inspect.assert_called_once()
        # Verify the render function received the warning in the AuditReport
        mock_render.assert_called_once()
        report_arg = mock_render.call_args[0][0]
        assert flagged_warning in report_arg.warnings, (
            f"Expected limitation warning in report.warnings, got: {report_arg.warnings}"
        )
