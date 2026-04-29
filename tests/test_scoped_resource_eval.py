# Feature: scoped-resource-policy-eval
"""Bug condition exploration tests for scoped Resource policy evaluation.

These tests encode the EXPECTED (correct) behavior. They are designed to
FAIL on unfixed code, confirming the bug exists:
- simulate_principal_access() only checks top-level EvalDecision and ignores
  ResourceSpecificResults[].EvalResourceDecision

**Validates: Requirements 1.1, 1.2, 2.1, 2.2**

**Security invariant**: these tests never call ``GetSecretValue``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.resolver import simulate_principal_access


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Generate valid secretsmanager action names
_SM_ACTIONS = st.sampled_from([
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:DeleteSecret",
    "secretsmanager:CreateSecret",
    "secretsmanager:DescribeSecret",
])

# Generate 1-4 ResourceSpecificResults entries, all with EvalResourceDecision == "allowed"
_RESOURCE_SPECIFIC_RESULTS_ALLOWED = st.lists(
    st.fixed_dictionaries({
        "EvalResourceName": st.just(
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds/prod-db-west/app_user-AbCdEf"
        ),
        "EvalResourceDecision": st.just("allowed"),
    }),
    min_size=1,
    max_size=4,
)


# Feature: scoped-resource-policy-eval, Property 1: Bug Condition
class TestProperty1ScopedResourceBugCondition:
    """Exploration tests that confirm the bug exists on unfixed code.

    Property 1: Bug Condition - Resource-Specific Allowed Actions Are Collected

    For any EvaluationResults entry where the top-level EvalDecision is not
    "allowed" but ResourceSpecificResults contains at least one entry with
    EvalResourceDecision == "allowed", the parsing loop SHALL collect that
    action name into the allowed list.

    **Validates: Requirements 1.1, 1.2, 2.1, 2.2**
    """

    @given(
        action=_SM_ACTIONS,
        resource_specific_results=_RESOURCE_SPECIFIC_RESULTS_ALLOWED,
    )
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_resource_specific_allowed_action_is_collected(
        self,
        action: str,
        resource_specific_results: list[dict],
    ) -> None:
        """An action with EvalDecision='implicitDeny' but ResourceSpecificResults
        containing EvalResourceDecision='allowed' MUST be collected.

        On unfixed code this FAILS because the parsing loop only checks the
        top-level EvalDecision and ignores ResourceSpecificResults entirely.

        **Validates: Requirements 1.1, 1.2, 2.1, 2.2**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        # Build a response where top-level is implicitDeny but
        # ResourceSpecificResults has allowed entries
        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": [
                {
                    "EvalActionName": action,
                    "EvalDecision": "implicitDeny",
                    "ResourceSpecificResults": resource_specific_results,
                }
            ]
        }

        result = simulate_principal_access(
            mock_session,
            ["arn:aws:iam::123456789012:role/ScopedResourceRole"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds/prod-db-west/app_user-AbCdEf",
        )

        # The action should be collected because ResourceSpecificResults
        # contains an allowed decision
        assert len(result.principals) == 1, (
            f"Expected 1 principal with access, got {len(result.principals)}. "
            f"Action '{action}' with EvalDecision='implicitDeny' and "
            f"ResourceSpecificResults[].EvalResourceDecision='allowed' was not collected."
        )
        assert action in result.principals[0].allowed_actions, (
            f"Action '{action}' should be in allowed_actions but got "
            f"{result.principals[0].allowed_actions}"
        )


# ---------------------------------------------------------------------------
# Strategies for Property 2: Preservation
# ---------------------------------------------------------------------------

# Non-"allowed" top-level decisions
_DENY_DECISIONS = st.sampled_from(["implicitDeny", "explicitDeny"])

# All three possible EvalDecision values
_ALL_DECISIONS = st.sampled_from(["allowed", "implicitDeny", "explicitDeny"])

# Generate ResourceSpecificResults entries where ALL decisions are deny
_RESOURCE_SPECIFIC_RESULTS_ALL_DENY = st.lists(
    st.fixed_dictionaries({
        "EvalResourceName": st.just(
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds/prod-db-west/app_user-AbCdEf"
        ),
        "EvalResourceDecision": _DENY_DECISIONS,
    }),
    min_size=1,
    max_size=4,
)


# Feature: scoped-resource-policy-eval, Property 2: Preservation
class TestProperty2PreservationBehavior:
    """Preservation tests that capture baseline behavior on UNFIXED code.

    Property 2: Preservation - Top-Level and Absent ResourceSpecificResults
    Behavior Unchanged

    For any EvaluationResults entry where either (a) the top-level EvalDecision
    is "allowed", or (b) ResourceSpecificResults is absent/empty, the parsing
    loop SHALL produce the same result as the original parsing loop, preserving
    existing behavior for Resource: * policies and responses without
    resource-specific results.

    These tests MUST PASS on unfixed code — they confirm the baseline behavior
    that the fix must preserve.

    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.6**
    """

    @given(action=_SM_ACTIONS)
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_top_level_allowed_no_resource_specific_results_collects_action(
        self,
        action: str,
    ) -> None:
        """A response with EvalDecision='allowed' and no ResourceSpecificResults
        collects the action (top-level allow path for Resource: * policies).

        **Validates: Requirements 3.1, 3.3**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": [
                {
                    "EvalActionName": action,
                    "EvalDecision": "allowed",
                }
            ]
        }

        result = simulate_principal_access(
            mock_session,
            ["arn:aws:iam::123456789012:role/WildcardResourceRole"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds/prod-db-west/app_user-AbCdEf",
        )

        assert len(result.principals) == 1, (
            f"Expected 1 principal with access, got {len(result.principals)}. "
            f"Action '{action}' with EvalDecision='allowed' should be collected."
        )
        assert action in result.principals[0].allowed_actions, (
            f"Action '{action}' should be in allowed_actions but got "
            f"{result.principals[0].allowed_actions}"
        )

    @given(action=_SM_ACTIONS)
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_top_level_allowed_empty_resource_specific_results_collects_action(
        self,
        action: str,
    ) -> None:
        """A response with EvalDecision='allowed' and empty ResourceSpecificResults
        collects the action (top-level allow path preserved).

        **Validates: Requirements 3.1, 3.3**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": [
                {
                    "EvalActionName": action,
                    "EvalDecision": "allowed",
                    "ResourceSpecificResults": [],
                }
            ]
        }

        result = simulate_principal_access(
            mock_session,
            ["arn:aws:iam::123456789012:role/WildcardResourceRole"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds/prod-db-west/app_user-AbCdEf",
        )

        assert len(result.principals) == 1, (
            f"Expected 1 principal with access, got {len(result.principals)}. "
            f"Action '{action}' with EvalDecision='allowed' and empty "
            f"ResourceSpecificResults should be collected."
        )
        assert action in result.principals[0].allowed_actions

    @given(
        action=_SM_ACTIONS,
        top_level_decision=_DENY_DECISIONS,
    )
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_deny_with_absent_resource_specific_results_does_not_collect(
        self,
        action: str,
        top_level_decision: str,
    ) -> None:
        """A response with EvalDecision='implicitDeny'/'explicitDeny' and absent
        ResourceSpecificResults does NOT collect the action (all-deny path).

        **Validates: Requirements 3.2, 3.3**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": [
                {
                    "EvalActionName": action,
                    "EvalDecision": top_level_decision,
                }
            ]
        }

        result = simulate_principal_access(
            mock_session,
            ["arn:aws:iam::123456789012:role/NoDenyRole"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds/prod-db-west/app_user-AbCdEf",
        )

        assert len(result.principals) == 0, (
            f"Expected 0 principals with access, got {len(result.principals)}. "
            f"Action '{action}' with EvalDecision='{top_level_decision}' and "
            f"absent ResourceSpecificResults should NOT be collected."
        )

    @given(
        action=_SM_ACTIONS,
        top_level_decision=_DENY_DECISIONS,
    )
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_deny_with_empty_resource_specific_results_does_not_collect(
        self,
        action: str,
        top_level_decision: str,
    ) -> None:
        """A response with EvalDecision='implicitDeny'/'explicitDeny' and empty
        ResourceSpecificResults does NOT collect the action (all-deny path).

        **Validates: Requirements 3.2, 3.3**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": [
                {
                    "EvalActionName": action,
                    "EvalDecision": top_level_decision,
                    "ResourceSpecificResults": [],
                }
            ]
        }

        result = simulate_principal_access(
            mock_session,
            ["arn:aws:iam::123456789012:role/NoDenyRole"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds/prod-db-west/app_user-AbCdEf",
        )

        assert len(result.principals) == 0, (
            f"Expected 0 principals with access, got {len(result.principals)}. "
            f"Action '{action}' with EvalDecision='{top_level_decision}' and "
            f"empty ResourceSpecificResults should NOT be collected."
        )

    @given(
        action=_SM_ACTIONS,
        top_level_decision=_DENY_DECISIONS,
        resource_specific_results=_RESOURCE_SPECIFIC_RESULTS_ALL_DENY,
    )
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_deny_with_all_deny_resource_specific_results_does_not_collect(
        self,
        action: str,
        top_level_decision: str,
        resource_specific_results: list[dict],
    ) -> None:
        """A response with EvalDecision not 'allowed' and ResourceSpecificResults
        where ALL entries are 'implicitDeny' or 'explicitDeny' does NOT collect
        the action.

        **Validates: Requirements 3.2, 3.6**
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": [
                {
                    "EvalActionName": action,
                    "EvalDecision": top_level_decision,
                    "ResourceSpecificResults": resource_specific_results,
                }
            ]
        }

        result = simulate_principal_access(
            mock_session,
            ["arn:aws:iam::123456789012:role/AllDenyRole"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds/prod-db-west/app_user-AbCdEf",
        )

        assert len(result.principals) == 0, (
            f"Expected 0 principals with access, got {len(result.principals)}. "
            f"Action '{action}' with EvalDecision='{top_level_decision}' and "
            f"all-deny ResourceSpecificResults should NOT be collected."
        )
