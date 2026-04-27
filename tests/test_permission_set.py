"""Property-based tests for permission set name extraction.

# Feature: secrets-audit-tool, Property 6: Permission set name extraction round-trip
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.classifier import extract_permission_set_name


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Valid permission set names: alphanumeric + hyphens, 1-50 chars.
# We avoid underscores to prevent ambiguity with the trailing _<hash> segment.
_perm_set_name_strategy = st.from_regex(r"[a-zA-Z][a-zA-Z0-9-]{0,49}", fullmatch=True)

# Hex hash: 12+ lowercase hex characters (matching the regex [a-f0-9]{12,})
_hex_hash_strategy = st.from_regex(r"[a-f0-9]{12,20}", fullmatch=True)

# Non-matching role names: names that should NOT match the AWSReservedSSO pattern
_non_matching_role_name = st.one_of(
    # Plain role names without the prefix
    st.from_regex(r"[a-zA-Z][a-zA-Z0-9_-]{2,30}", fullmatch=True),
    # Prefix but missing hash
    st.builds(lambda n: f"AWSReservedSSO_{n}", n=_perm_set_name_strategy),
    # Prefix but hash too short (< 12 hex chars)
    st.builds(
        lambda n, h: f"AWSReservedSSO_{n}_{h}",
        n=_perm_set_name_strategy,
        h=st.from_regex(r"[a-f0-9]{1,11}", fullmatch=True),
    ),
)


# ---------------------------------------------------------------------------
# Property test class
# ---------------------------------------------------------------------------


# Feature: secrets-audit-tool, Property 6: Permission set name extraction round-trip
class TestProperty6PermissionSetNameExtraction:
    """Property 6: Permission set name extraction round-trip.

    For any valid permission set name (alphanumeric + hyphens) and any valid
    hex hash of 12+ characters, constructing a role name of the form
    ``AWSReservedSSO_<NAME>_<hash>`` and then calling
    ``extract_permission_set_name`` should return the original permission
    set name.

    **Validates: Requirements 2.4**
    """

    @given(
        name=_perm_set_name_strategy,
        hex_hash=_hex_hash_strategy,
    )
    @settings(max_examples=100)
    def test_round_trip_extracts_original_name(
        self,
        name: str,
        hex_hash: str,
    ) -> None:
        """Constructing AWSReservedSSO_<name>_<hash> and extracting returns <name>."""
        # Feature: secrets-audit-tool, Property 6: Permission set name extraction round-trip
        role_name = f"AWSReservedSSO_{name}_{hex_hash}"
        extracted = extract_permission_set_name(role_name)
        assert extracted == name, (
            f"Expected '{name}' but got '{extracted}' for role_name='{role_name}'"
        )

    @given(role_name=_non_matching_role_name)
    @settings(max_examples=100)
    def test_non_matching_names_return_none(
        self,
        role_name: str,
    ) -> None:
        """Role names not matching AWSReservedSSO_<name>_<hash> return None."""
        # Feature: secrets-audit-tool, Property 6: Permission set name extraction round-trip
        result = extract_permission_set_name(role_name)
        assert result is None, (
            f"Expected None but got '{result}' for role_name='{role_name}'"
        )
