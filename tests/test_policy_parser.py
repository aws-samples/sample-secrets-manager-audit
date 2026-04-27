"""Property-based tests for resource-based policy parsing.

# Feature: secrets-audit-tool, Property 5: Resource-based policy parsing extracts all Allow principals
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.resolver import get_resource_policy_principals


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Strategy: valid IAM ARNs (roles and users)
_arn_strategy = st.from_regex(
    r"arn:aws:iam::\d{12}:(role|user)/[a-zA-Z0-9_+=,.@-]{1,30}",
    fullmatch=True,
)

# Strategy: principal field formats
# A principal can be a plain ARN string, or a dict with "AWS" key holding
# a single ARN or a list of ARNs.
_principal_field_strategy = st.one_of(
    # Plain string ARN
    _arn_strategy.map(lambda arn: arn),
    # Dict with single ARN
    _arn_strategy.map(lambda arn: {"AWS": arn}),
    # Dict with list of ARNs
    st.lists(_arn_strategy, min_size=1, max_size=5).map(lambda arns: {"AWS": arns}),
)

# Strategy: a single policy statement (effect + principal + action)
_secretsmanager_actions = st.sampled_from([
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:DeleteSecret",
    "secretsmanager:CreateSecret",
    "secretsmanager:DescribeSecret",
    "secretsmanager:*",
])


@st.composite
def _statement_strategy(draw: st.DrawFn) -> tuple[dict, str, set[str]]:
    """Generate a single IAM policy statement and its metadata.

    Returns (statement_dict, effect, set_of_arns_in_this_statement).
    """
    effect = draw(st.sampled_from(["Allow", "Deny"]))
    principal_field = draw(_principal_field_strategy)
    actions = draw(st.lists(_secretsmanager_actions, min_size=1, max_size=4))

    # Extract the ARNs from the principal field for verification
    arns: set[str] = set()
    if isinstance(principal_field, str):
        if principal_field != "*":
            arns.add(principal_field)
    elif isinstance(principal_field, dict):
        aws_val = principal_field.get("AWS")
        if isinstance(aws_val, str):
            if aws_val != "*":
                arns.add(aws_val)
        elif isinstance(aws_val, list):
            arns.update(v for v in aws_val if isinstance(v, str) and v != "*")

    statement = {
        "Effect": effect,
        "Principal": principal_field,
        "Action": actions if len(actions) > 1 else actions[0],
        "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf",
    }

    return statement, effect, arns


@st.composite
def _policy_strategy(draw: st.DrawFn) -> tuple[dict, set[str]]:
    """Generate a full IAM policy document and the expected set of Allow ARNs.

    Returns (policy_dict, expected_allow_arns).
    """
    statements_data = draw(
        st.lists(_statement_strategy(), min_size=1, max_size=8)
    )

    statements = []
    expected_allow_arns: set[str] = set()

    for stmt_dict, effect, arns in statements_data:
        statements.append(stmt_dict)
        if effect == "Allow":
            expected_allow_arns.update(arns)

    policy = {
        "Version": "2012-10-17",
        "Statement": statements,
    }

    return policy, expected_allow_arns


# ---------------------------------------------------------------------------
# Property test
# ---------------------------------------------------------------------------


# Feature: secrets-audit-tool, Property 5: Resource-based policy parsing extracts all Allow principals
class TestProperty5ResourcePolicyParsing:
    """Property 5: Resource-based policy parsing extracts all Allow principals.

    For any valid IAM policy JSON document, get_resource_policy_principals
    should return a principal for every unique principal ARN that appears in
    a Statement with "Effect": "Allow". No principals from Deny statements
    should be included. The returned set should be exactly the set of Allow
    principals.

    **Validates: Requirements 1.13**
    """

    @given(data=_policy_strategy())
    @settings(max_examples=100)
    def test_returned_principals_match_allow_set(
        self, data: tuple[dict, set[str]]
    ) -> None:
        """The set of returned principal ARNs must equal the Allow ARN set."""
        # Feature: secrets-audit-tool, Property 5: Resource-based policy parsing extracts all Allow principals
        policy_doc, expected_allow_arns = data

        # Mock the secretsmanager client to return our generated policy
        mock_client = MagicMock()
        mock_client.get_resource_policy.return_value = {
            "ResourcePolicy": json.dumps(policy_doc),
        }
        # Ensure the client doesn't have a matching exception class
        mock_client.exceptions = MagicMock()
        mock_client.exceptions.ResourceNotFoundException = type(
            "ResourceNotFoundException", (Exception,), {}
        )

        mock_session = MagicMock()
        mock_session.client.return_value = mock_client

        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf"
        results = get_resource_policy_principals(mock_session, secret_arn)

        returned_arns = {r.principal_arn for r in results}

        assert returned_arns == expected_allow_arns, (
            f"Expected Allow ARNs {expected_allow_arns}, got {returned_arns}. "
            f"Policy: {json.dumps(policy_doc, indent=2)}"
        )

    @given(data=_policy_strategy())
    @settings(max_examples=100)
    def test_no_deny_principals_in_results(
        self, data: tuple[dict, set[str]]
    ) -> None:
        """No principal from a Deny-only statement should appear in results."""
        # Feature: secrets-audit-tool, Property 5: Resource-based policy parsing extracts all Allow principals
        policy_doc, expected_allow_arns = data

        # Collect ARNs that appear ONLY in Deny statements
        deny_only_arns: set[str] = set()
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") == "Deny":
                principal_field = stmt.get("Principal", {})
                arns: set[str] = set()
                if isinstance(principal_field, str) and principal_field != "*":
                    arns.add(principal_field)
                elif isinstance(principal_field, dict):
                    aws_val = principal_field.get("AWS")
                    if isinstance(aws_val, str) and aws_val != "*":
                        arns.add(aws_val)
                    elif isinstance(aws_val, list):
                        arns.update(v for v in aws_val if isinstance(v, str) and v != "*")
                deny_only_arns.update(arns)
        # Remove any ARN that also appears in an Allow statement
        deny_only_arns -= expected_allow_arns

        mock_client = MagicMock()
        mock_client.get_resource_policy.return_value = {
            "ResourcePolicy": json.dumps(policy_doc),
        }
        mock_client.exceptions = MagicMock()
        mock_client.exceptions.ResourceNotFoundException = type(
            "ResourceNotFoundException", (Exception,), {}
        )

        mock_session = MagicMock()
        mock_session.client.return_value = mock_client

        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf"
        results = get_resource_policy_principals(mock_session, secret_arn)

        returned_arns = {r.principal_arn for r in results}

        # No deny-only ARN should appear in the results
        leaked = returned_arns & deny_only_arns
        assert not leaked, (
            f"Deny-only ARNs leaked into results: {leaked}. "
            f"Policy: {json.dumps(policy_doc, indent=2)}"
        )
