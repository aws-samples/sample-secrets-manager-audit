# Feature: tag-based-policy-eval
"""Bug condition exploration tests for tag-based policy evaluation.

These tests encode the EXPECTED (correct) behavior. They are designed to
FAIL on unfixed code, confirming the bug exists:
- simulate_principal_access() does not pass ContextEntries or ResourceHandlingOption
- SecretMetadata has no tags field
- resolve_secret() discards Tags from DescribeSecret response

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3**

**Security invariant**: these tests never call ``GetSecretValue``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.models import SecretMetadata
from secrets_audit.resolver import SimulationResult, simulate_principal_access


# Feature: tag-based-policy-eval, Property 1: Bug Condition
class TestProperty1TagBasedPolicyBugCondition:
    """Exploration tests that confirm the bug exists on unfixed code.

    **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3**
    """

    @given(
        tags=st.dictionaries(
            keys=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10),
            values=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=10),
            min_size=1,
            max_size=5,
        )
    )
    @settings(max_examples=100)
    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_context_entries_passed_to_simulator(self, tags: dict[str, str]) -> None:
        """simulate_principal_access must pass ContextEntries with resource tags.

        On unfixed code this FAILS because the resource_tags parameter does not
        exist on simulate_principal_access().
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        # Simulate a single principal that gets "allowed" for one action
        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": [
                {"EvalActionName": "secretsmanager:GetSecretValue", "EvalDecision": "allowed"}
            ]
        }

        result = simulate_principal_access(
            mock_session,
            ["arn:aws:iam::123456789012:role/test-role"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret",
            resource_tags=tags,
        )

        # Verify the call was made
        mock_client.simulate_principal_policy.assert_called_once()
        call_kwargs = mock_client.simulate_principal_policy.call_args[1]

        # Must include ContextEntries
        assert "ContextEntries" in call_kwargs, "ContextEntries missing from SimulatePrincipalPolicy call"
        context_entries = call_kwargs["ContextEntries"]

        # Two entries per tag (aws:ResourceTag + secretsmanager:ResourceTag)
        assert len(context_entries) == len(tags) * 2

        # Each entry must have the correct format
        expected_keys = set()
        for k in tags:
            expected_keys.add(f"aws:ResourceTag/{k}")
            expected_keys.add(f"secretsmanager:ResourceTag/{k}")
        actual_keys = {e["ContextKeyName"] for e in context_entries}
        assert actual_keys == expected_keys

        for entry in context_entries:
            tag_key = entry["ContextKeyName"].split("/", 1)[1]
            assert entry["ContextKeyValues"] == [tags[tag_key]]
            assert entry["ContextKeyType"] == "string"

        # ResourceHandlingOption is NOT used — Secrets Manager actions don't support it
        assert "ResourceHandlingOption" not in call_kwargs

    def test_secret_metadata_has_tags_field(self) -> None:
        """SecretMetadata must have a tags field.

        On unfixed code this FAILS because the tags field does not exist.
        """
        meta = SecretMetadata(name="test", arn="arn:test")
        assert hasattr(meta, "tags"), "SecretMetadata missing 'tags' attribute"
        assert isinstance(meta.tags, dict), "SecretMetadata.tags should be a dict"
        assert meta.tags == {}, "SecretMetadata.tags should default to empty dict"

    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_resolve_secret_captures_tags(self) -> None:
        """resolve_secret must capture Tags from DescribeSecret response.

        On unfixed code this FAILS because tags aren't captured.
        """
        from secrets_audit.resolver import resolve_secret

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.describe_secret.return_value = {
            "Name": "rds/prod-db-west/app_user",
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds/prod-db-west/app_user-AbCdEf",
            "Description": "Production DB credentials",
            "Tags": [
                {"Key": "env", "Value": "prod"},
                {"Key": "team", "Value": "platform"},
            ],
        }
        # Ensure ResourceNotFoundException is available on the mock client
        mock_client.exceptions.ResourceNotFoundException = type(
            "ResourceNotFoundException", (Exception,), {}
        )

        result = resolve_secret(mock_session, "rds/prod-db-west/app_user")

        assert hasattr(result, "tags"), "SecretMetadata missing 'tags' attribute"
        assert result.tags == {"env": "prod", "team": "platform"}

    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_resolve_secret_handles_no_tags(self) -> None:
        """resolve_secret must handle missing Tags gracefully (empty dict).

        On unfixed code this FAILS because tags field doesn't exist.
        """
        from secrets_audit.resolver import resolve_secret

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.describe_secret.return_value = {
            "Name": "test-secret",
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf",
        }
        mock_client.exceptions.ResourceNotFoundException = type(
            "ResourceNotFoundException", (Exception,), {}
        )

        result = resolve_secret(mock_session, "test-secret")

        assert hasattr(result, "tags"), "SecretMetadata missing 'tags' attribute"
        assert result.tags == {}

    @patch("secrets_audit.resolver._BATCH_SLEEP", 0)
    def test_resource_handling_option_not_used(self) -> None:
        """ResourceHandlingOption must NOT be passed — Secrets Manager doesn't support it.

        On unfixed code this FAILS because ResourceHandlingOption was passed.
        """
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.simulate_principal_policy.return_value = {
            "EvaluationResults": []
        }

        simulate_principal_access(
            mock_session,
            ["arn:aws:iam::123456789012:role/test-role"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
            resource_tags={},
        )

        call_kwargs = mock_client.simulate_principal_policy.call_args[1]
        assert "ResourceHandlingOption" not in call_kwargs
