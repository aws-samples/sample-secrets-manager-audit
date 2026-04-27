"""Property-based tests for access level derivation.

# Feature: secrets-audit-tool, Property 2: Access level derivation from allowed actions
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.models import AccessLevel
from secrets_audit.resolver import (
    _ADMIN_ACTIONS,
    _READ_ACTIONS,
    _WRITE_ACTIONS,
    derive_access_level,
)

# All known secretsmanager actions used by the tool
_ALL_ACTIONS: list[str] = sorted(
    _READ_ACTIONS | _WRITE_ACTIONS | _ADMIN_ACTIONS
)

# Strategy: non-empty subsets of the full action set
_action_subsets = st.frozensets(
    st.sampled_from(_ALL_ACTIONS), min_size=1
)


# Feature: secrets-audit-tool, Property 2: Access level derivation from allowed actions
class TestProperty2AccessLevelDerivation:
    """Property 2: Access level derivation from allowed actions.

    For any non-empty subset of secretsmanager actions, derive_access_level
    should return the correct AccessLevel following the precedence rules.

    **Validates: Requirements 1.4**
    """

    @given(actions=_action_subsets)
    @settings(max_examples=100)
    def test_admin_actions_always_yield_admin(self, actions: frozenset[str]) -> None:
        """If any admin action is present, the result MUST be Admin."""
        # Feature: secrets-audit-tool, Property 2: Access level derivation from allowed actions
        if actions & _ADMIN_ACTIONS:
            result = derive_access_level(list(actions))
            assert result == AccessLevel.ADMIN

    @given(actions=st.frozensets(st.sampled_from(sorted(_READ_ACTIONS)), min_size=1))
    @settings(max_examples=100)
    def test_read_only_actions_yield_read(self, actions: frozenset[str]) -> None:
        """If only read actions are present, the result MUST be Read."""
        # Feature: secrets-audit-tool, Property 2: Access level derivation from allowed actions
        result = derive_access_level(list(actions))
        assert result == AccessLevel.READ

    @given(actions=st.frozensets(st.sampled_from(sorted(_WRITE_ACTIONS)), min_size=1))
    @settings(max_examples=100)
    def test_write_only_actions_yield_write(self, actions: frozenset[str]) -> None:
        """If only write actions are present (no read), the result MUST be Write."""
        # Feature: secrets-audit-tool, Property 2: Access level derivation from allowed actions
        result = derive_access_level(list(actions))
        assert result == AccessLevel.WRITE

    @given(
        read_actions=st.frozensets(st.sampled_from(sorted(_READ_ACTIONS)), min_size=1),
        write_actions=st.frozensets(st.sampled_from(sorted(_WRITE_ACTIONS)), min_size=1),
    )
    @settings(max_examples=100)
    def test_mixed_read_write_actions_yield_read_write(
        self,
        read_actions: frozenset[str],
        write_actions: frozenset[str],
    ) -> None:
        """If both read and write actions are present (no admin), the result MUST be Read/Write."""
        # Feature: secrets-audit-tool, Property 2: Access level derivation from allowed actions
        combined = read_actions | write_actions
        result = derive_access_level(list(combined))
        assert result == AccessLevel.READ_WRITE

    @given(actions=_action_subsets)
    @settings(max_examples=100)
    def test_admin_precedence_over_all(self, actions: frozenset[str]) -> None:
        """Admin takes precedence: adding any admin action to any set must yield Admin."""
        # Feature: secrets-audit-tool, Property 2: Access level derivation from allowed actions
        for admin_action in _ADMIN_ACTIONS:
            augmented = actions | {admin_action}
            result = derive_access_level(list(augmented))
            assert result == AccessLevel.ADMIN, (
                f"Expected Admin when {admin_action} added to {actions}, got {result}"
            )

    @given(actions=_action_subsets)
    @settings(max_examples=100)
    def test_classification_is_exhaustive(self, actions: frozenset[str]) -> None:
        """Every non-empty subset must map to one of the four access levels."""
        # Feature: secrets-audit-tool, Property 2: Access level derivation from allowed actions
        result = derive_access_level(list(actions))
        assert result in (
            AccessLevel.READ,
            AccessLevel.WRITE,
            AccessLevel.READ_WRITE,
            AccessLevel.ADMIN,
        )
