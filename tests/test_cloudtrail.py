"""Property-based tests for CloudTrail last-accessed enrichment.

# Feature: secrets-audit-tool, Property 3: CloudTrail last-accessed selects most recent event per principal
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from secrets_audit.cloudtrail import (
    CLOUDTRAIL_UNAVAILABLE,
    NO_RECENT_ACCESS,
    get_last_accessed,
)

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Generate realistic IAM role/user ARNs as principal identifiers
_principal_arns = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789",
    min_size=1,
    max_size=10,
).map(lambda name: f"arn:aws:iam::123456789012:role/{name}")

# Timestamps within the last 90 days (the default lookback window).
# hypothesis requires naive min/max; timezone is applied via the timezones param.
_recent_timestamps = st.datetimes(
    min_value=datetime(2025, 1, 1),
    max_value=datetime(2025, 12, 31),
    timezones=st.just(timezone.utc),
)

# A single (principal_arn, timestamp) event tuple
_event_tuples = st.tuples(_principal_arns, _recent_timestamps)

# A list of event tuples (0 to 30 events)
_event_lists = st.lists(_event_tuples, min_size=0, max_size=30)

# A set of principal ARNs to query (1 to 10 principals)
_queried_arns = st.frozensets(_principal_arns, min_size=1, max_size=10)

# Fixed secret ARN used across all tests
_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test/secret-AbCdEf"  # nosec B105


def _build_mock_events(
    event_tuples: list[tuple[str, datetime]],
    secret_arn: str,
) -> list[dict]:
    """Convert (principal_arn, timestamp) tuples into mock CloudTrail event dicts."""
    events = []
    for principal_arn, timestamp in event_tuples:
        events.append(
            {
                "EventTime": timestamp,
                "CloudTrailEvent": json.dumps(
                    {"userIdentity": {"arn": principal_arn}}
                ),
                "Resources": [{"ResourceName": secret_arn}],
                "Username": principal_arn.rsplit("/", 1)[-1],
                "EventName": "GetSecretValue",
            }
        )
    return events


# Feature: secrets-audit-tool, Property 3: CloudTrail last-accessed selects most recent event per principal
class TestProperty3CloudTrailLastAccessed:
    """Property 3: CloudTrail last-accessed selects most recent event per principal.

    For any list of CloudTrail events and any set of principal ARNs to query,
    get_last_accessed should return the maximum timestamp for each principal
    that has events, "No recent access (>90 days)" for principals with no
    events, and the mapping should contain exactly the queried principal ARNs
    as keys.

    **Validates: Requirements 1.5, 1.6**
    """

    @given(
        event_tuples=_event_lists,
        queried_arns=_queried_arns,
    )
    @settings(max_examples=100)
    def test_key_set_matches_queried_arns(
        self,
        event_tuples: list[tuple[str, datetime]],
        queried_arns: frozenset[str],
    ) -> None:
        """The returned dict keys must be exactly the queried principal ARNs."""
        # Feature: secrets-audit-tool, Property 3: CloudTrail last-accessed selects most recent event per principal
        mock_events = _build_mock_events(event_tuples, _SECRET_ARN)

        with patch(
            "secrets_audit.cloudtrail._fetch_events", return_value=mock_events
        ):
            result = get_last_accessed(
                session=None,  # type: ignore[arg-type]
                secret_arn=_SECRET_ARN,
                principal_arns=list(queried_arns),
            )

        assert set(result.keys()) == set(queried_arns)

    @given(
        event_tuples=_event_lists,
        queried_arns=_queried_arns,
    )
    @settings(max_examples=100)
    def test_max_timestamp_per_principal(
        self,
        event_tuples: list[tuple[str, datetime]],
        queried_arns: frozenset[str],
    ) -> None:
        """For principals with events, the value must be the maximum timestamp."""
        # Feature: secrets-audit-tool, Property 3: CloudTrail last-accessed selects most recent event per principal
        mock_events = _build_mock_events(event_tuples, _SECRET_ARN)

        with patch(
            "secrets_audit.cloudtrail._fetch_events", return_value=mock_events
        ):
            result = get_last_accessed(
                session=None,  # type: ignore[arg-type]
                secret_arn=_SECRET_ARN,
                principal_arns=list(queried_arns),
            )

        # Compute expected max timestamps from the event tuples
        expected_max: dict[str, datetime] = {}
        for arn, ts in event_tuples:
            if arn in queried_arns:
                if arn not in expected_max or ts > expected_max[arn]:
                    expected_max[arn] = ts

        for arn in queried_arns:
            if arn in expected_max:
                assert result[arn] == expected_max[arn], (
                    f"Expected max timestamp {expected_max[arn]} for {arn}, "
                    f"got {result[arn]}"
                )

    @given(
        event_tuples=_event_lists,
        queried_arns=_queried_arns,
    )
    @settings(max_examples=100)
    def test_no_events_yields_no_recent_access(
        self,
        event_tuples: list[tuple[str, datetime]],
        queried_arns: frozenset[str],
    ) -> None:
        """Principals with no events must get the NO_RECENT_ACCESS status string."""
        # Feature: secrets-audit-tool, Property 3: CloudTrail last-accessed selects most recent event per principal
        mock_events = _build_mock_events(event_tuples, _SECRET_ARN)

        with patch(
            "secrets_audit.cloudtrail._fetch_events", return_value=mock_events
        ):
            result = get_last_accessed(
                session=None,  # type: ignore[arg-type]
                secret_arn=_SECRET_ARN,
                principal_arns=list(queried_arns),
            )

        # Principals that appear in events
        event_principals = {arn for arn, _ in event_tuples}

        for arn in queried_arns:
            if arn not in event_principals:
                assert result[arn] == NO_RECENT_ACCESS, (
                    f"Expected '{NO_RECENT_ACCESS}' for {arn} with no events, "
                    f"got {result[arn]}"
                )

    @given(
        event_tuples=_event_lists,
        queried_arns=_queried_arns,
    )
    @settings(max_examples=100)
    def test_values_are_datetime_or_status_string(
        self,
        event_tuples: list[tuple[str, datetime]],
        queried_arns: frozenset[str],
    ) -> None:
        """Every value must be either a datetime or the NO_RECENT_ACCESS string."""
        # Feature: secrets-audit-tool, Property 3: CloudTrail last-accessed selects most recent event per principal
        mock_events = _build_mock_events(event_tuples, _SECRET_ARN)

        with patch(
            "secrets_audit.cloudtrail._fetch_events", return_value=mock_events
        ):
            result = get_last_accessed(
                session=None,  # type: ignore[arg-type]
                secret_arn=_SECRET_ARN,
                principal_arns=list(queried_arns),
            )

        for arn, value in result.items():
            assert isinstance(value, datetime) or value == NO_RECENT_ACCESS, (
                f"Unexpected value type for {arn}: {value!r}"
            )

    @given(queried_arns=_queried_arns)
    @settings(max_examples=100)
    def test_cloudtrail_unavailable_yields_unknown_status(
        self,
        queried_arns: frozenset[str],
    ) -> None:
        """When CloudTrail is unavailable, all values must be CLOUDTRAIL_UNAVAILABLE."""
        # Feature: secrets-audit-tool, Property 3: CloudTrail last-accessed selects most recent event per principal
        from secrets_audit.cloudtrail import _CloudTrailUnavailable

        with patch(
            "secrets_audit.cloudtrail._fetch_events",
            side_effect=_CloudTrailUnavailable("access denied"),
        ):
            result = get_last_accessed(
                session=None,  # type: ignore[arg-type]
                secret_arn=_SECRET_ARN,
                principal_arns=list(queried_arns),
            )

        assert set(result.keys()) == set(queried_arns)
        for arn, value in result.items():
            assert value == CLOUDTRAIL_UNAVAILABLE, (
                f"Expected '{CLOUDTRAIL_UNAVAILABLE}' for {arn}, got {value!r}"
            )


# Feature: cloudtrail-resource-filter, Property 2: Preservation
class TestProperty2Preservation:
    """Property 2: Preservation — get_last_accessed Return Contract.

    These tests verify preservation behaviors that are NOT covered by the
    existing TestProperty3CloudTrailLastAccessed class: the empty principal
    list fast path (2e) and progress callback invocation (2f).

    These tests MUST PASS on the current unfixed code.

    **Validates: Requirements 3.5, 3.6**
    """

    def test_empty_principal_list_fast_path(self) -> None:
        """Sub-property 2e: empty principal_arns returns {} without calling _fetch_events.

        When principal_arns is empty, get_last_accessed() must return an empty
        dict immediately and must NOT invoke _fetch_events at all.
        """
        # Feature: cloudtrail-resource-filter, Property 2: Preservation
        with patch("secrets_audit.cloudtrail._fetch_events") as mock_fetch:
            result = get_last_accessed(
                session=None,  # type: ignore[arg-type]
                secret_arn=_SECRET_ARN,
                principal_arns=[],
            )

        assert result == {}, f"Expected empty dict, got {result!r}"
        mock_fetch.assert_not_called()

    def test_progress_callback_invocation(self) -> None:
        """Sub-property 2f: _fetch_events invokes the progress callback during pagination.

        When a progress callback is provided and CloudTrail returns multiple
        pages, _fetch_events must call the callback at least once per page.
        """
        # Feature: cloudtrail-resource-filter, Property 2: Preservation
        from unittest.mock import MagicMock

        mock_client = MagicMock()
        # Simulate two pages of results
        mock_client.lookup_events.side_effect = [
            {
                "Events": [
                    {
                        "EventTime": datetime(2025, 6, 1, tzinfo=timezone.utc),
                        "CloudTrailEvent": json.dumps(
                            {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/user1"}}
                        ),
                        "Resources": [{"ResourceName": _SECRET_ARN}],
                        "Username": "user1",
                        "EventName": "GetSecretValue",
                    }
                ],
                "NextToken": "page2",
            },
            {
                "Events": [
                    {
                        "EventTime": datetime(2025, 6, 2, tzinfo=timezone.utc),
                        "CloudTrailEvent": json.dumps(
                            {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/user2"}}
                        ),
                        "Resources": [{"ResourceName": _SECRET_ARN}],
                        "Username": "user2",
                        "EventName": "GetSecretValue",
                    }
                ],
            },
        ]

        mock_session = MagicMock()
        mock_session.client.return_value = mock_client

        progress_calls: list[str] = []

        def progress_cb(msg: str) -> None:
            progress_calls.append(msg)

        from secrets_audit.cloudtrail import _fetch_events

        _fetch_events(mock_session, _SECRET_ARN, lookback_days=90, progress=progress_cb)

        # The callback must have been invoked at least once per page (2 pages)
        assert len(progress_calls) >= 2, (
            f"Expected progress callback to be called at least 2 times, "
            f"got {len(progress_calls)} call(s): {progress_calls}"
        )


# ---------------------------------------------------------------------------
# Hypothesis strategies for bug condition exploration
# ---------------------------------------------------------------------------

# Generate valid Secrets Manager ARNs with random secret names
_secret_names = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789/-_",
    min_size=1,
    max_size=20,
)

_secret_arns = _secret_names.map(
    lambda name: f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{name}-AbCdEf"
)

# Event names that CloudTrail may return for a secret resource
_EVENT_NAMES = ["GetSecretValue", "DescribeSecret", "GetResourcePolicy", "PutSecretValue"]

_mixed_event_names = st.lists(
    st.sampled_from(_EVENT_NAMES),
    min_size=1,
    max_size=20,
)


def _build_mixed_event_name_events(
    event_names: list[str],
    secret_arn: str,
) -> list[dict]:
    """Build mock CloudTrail events with varying EventName values."""
    events = []
    for i, event_name in enumerate(event_names):
        events.append(
            {
                "EventTime": datetime(2025, 6, 1, tzinfo=timezone.utc),
                "CloudTrailEvent": json.dumps(
                    {"userIdentity": {"arn": f"arn:aws:iam::123456789012:role/user{i}"}}
                ),
                "Resources": [{"ResourceName": secret_arn}],
                "Username": f"user{i}",
                "EventName": event_name,
            }
        )
    return events


# Feature: cloudtrail-resource-filter, Property 1: Bug Condition
class TestProperty1BugCondition:
    """Property 1: Bug Condition — ResourceName Filter and EventName Post-Filter.

    These tests encode the EXPECTED (correct) behavior. They are designed to
    FAIL on the unfixed code, thereby confirming the bug exists.

    **Validates: Requirements 2.1, 2.2**
    """

    @given(secret_arn=_secret_arns)
    @settings(max_examples=100)
    def test_lookup_attributes_uses_resource_name_filter(
        self,
        secret_arn: str,
    ) -> None:
        """Sub-property 1a: _fetch_events must filter by ResourceName, not EventName.

        Generates random valid secret ARNs and asserts that the kwargs passed
        to lookup_events use AttributeKey == "ResourceName" with the secret ARN
        as the value.

        On unfixed code this FAILS because the key is "EventName" and the value
        is "GetSecretValue".
        """
        # Feature: cloudtrail-resource-filter, Property 1: Bug Condition
        from secrets_audit.cloudtrail import _fetch_events
        from unittest.mock import MagicMock

        captured_kwargs: list[dict] = []

        mock_client = MagicMock()

        def capture_lookup_events(**kwargs: object) -> dict:
            captured_kwargs.append(kwargs)
            return {"Events": [], "NextToken": None}

        mock_client.lookup_events.side_effect = capture_lookup_events

        mock_session = MagicMock()
        mock_session.client.return_value = mock_client

        _fetch_events(mock_session, secret_arn, lookback_days=90)

        assert len(captured_kwargs) >= 1, "lookup_events was never called"
        attrs = captured_kwargs[0]["LookupAttributes"]
        assert attrs[0]["AttributeKey"] == "ResourceName", (
            f"Expected AttributeKey 'ResourceName', got '{attrs[0]['AttributeKey']}'"
        )
        assert attrs[0]["AttributeValue"] == secret_arn, (
            f"Expected AttributeValue '{secret_arn}', got '{attrs[0]['AttributeValue']}'"
        )

    @given(event_names=_mixed_event_names)
    @settings(max_examples=100)
    def test_event_name_post_filter(
        self,
        event_names: list[str],
    ) -> None:
        """Sub-property 1b: _fetch_events must post-filter to only GetSecretValue events.

        Creates mock events with mixed EventName values and asserts that ALL
        returned events have EventName == "GetSecretValue".

        On unfixed code this FAILS because no EventName post-filter exists —
        all events are returned regardless of EventName.
        """
        # Feature: cloudtrail-resource-filter, Property 1: Bug Condition
        from secrets_audit.cloudtrail import _fetch_events
        from unittest.mock import MagicMock

        mock_events = _build_mixed_event_name_events(event_names, _SECRET_ARN)

        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {
            "Events": mock_events,
        }

        mock_session = MagicMock()
        mock_session.client.return_value = mock_client

        result = _fetch_events(mock_session, _SECRET_ARN, lookback_days=90)

        for event in result:
            assert event["EventName"] == "GetSecretValue", (
                f"Expected only GetSecretValue events, got EventName='{event['EventName']}'"
            )

    def test_event_matches_secret_not_called(self) -> None:
        """Sub-property 1c: get_last_accessed must NOT call _event_matches_secret.

        After the fix, server-side ResourceName filtering replaces the
        client-side _event_matches_secret() check. The function should
        either not exist or not be called.

        On unfixed code this FAILS because _event_matches_secret is called
        for every event.
        """
        # Feature: cloudtrail-resource-filter, Property 1: Bug Condition
        import secrets_audit.cloudtrail as ct_module

        # If the function has been removed entirely, the fix is confirmed
        if not hasattr(ct_module, "_event_matches_secret"):
            return  # Function removed — fix confirmed

        mock_events = _build_mock_events(
            [("arn:aws:iam::123456789012:role/testuser", datetime(2025, 6, 1, tzinfo=timezone.utc))],
            _SECRET_ARN,
        )

        with (
            patch("secrets_audit.cloudtrail._fetch_events", return_value=mock_events),
            patch("secrets_audit.cloudtrail._event_matches_secret", wraps=None) as mock_matches,
        ):
            mock_matches.return_value = True
            get_last_accessed(
                session=None,  # type: ignore[arg-type]
                secret_arn=_SECRET_ARN,
                principal_arns=["arn:aws:iam::123456789012:role/testuser"],
            )

        assert mock_matches.call_count == 0, (
            f"Expected _event_matches_secret to not be called, "
            f"but it was called {mock_matches.call_count} time(s)"
        )


# ---------------------------------------------------------------------------
# Bug 2 validation: ARN normalization for CloudTrail matching
# Feature: cloudtrail-resource-filter, ARN normalization
# ---------------------------------------------------------------------------

from secrets_audit.cloudtrail import _normalize_role_name


class TestARNNormalization:
    """Validate that _normalize_role_name correctly extracts role names
    from both IAM and STS ARN formats, enabling CloudTrail event matching."""

    def test_sts_assumed_role_extracts_role_name(self) -> None:
        """STS assumed-role ARN → bare role name."""
        arn = "arn:aws:sts::724419084136:assumed-role/AWSReservedSSO_AWSAdministratorAccess_ccf94df6ca2a4458/Joe.Bowman@lineagelogistics.com"
        assert _normalize_role_name(arn) == "AWSReservedSSO_AWSAdministratorAccess_ccf94df6ca2a4458"

    def test_iam_role_with_path_extracts_role_name(self) -> None:
        """IAM role ARN with SSO path → bare role name."""
        arn = "arn:aws:iam::724419084136:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_AWSAdministratorAccess_ccf94df6ca2a4458"
        assert _normalize_role_name(arn) == "AWSReservedSSO_AWSAdministratorAccess_ccf94df6ca2a4458"

    def test_iam_role_without_path_extracts_role_name(self) -> None:
        """IAM role ARN without path → bare role name."""
        arn = "arn:aws:iam::123456789012:role/eks-pod-role"
        assert _normalize_role_name(arn) == "eks-pod-role"

    def test_sts_and_iam_match_for_sso_role(self) -> None:
        """STS and IAM ARNs for the same SSO role normalize to the same key."""
        sts = "arn:aws:sts::724419084136:assumed-role/AWSReservedSSO_AWSAdministratorAccess_ccf94df6ca2a4458/session"
        iam = "arn:aws:iam::724419084136:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_AWSAdministratorAccess_ccf94df6ca2a4458"
        assert _normalize_role_name(sts) == _normalize_role_name(iam)

    def test_sts_and_iam_match_for_plain_role(self) -> None:
        """STS and IAM ARNs for a plain role normalize to the same key."""
        sts = "arn:aws:sts::123456789012:assumed-role/my-role/botocore-session-123"
        iam = "arn:aws:iam::123456789012:role/my-role"
        assert _normalize_role_name(sts) == _normalize_role_name(iam)

    def test_iam_user_keeps_user_prefix(self) -> None:
        """IAM user ARN normalizes with user/ prefix to avoid role collisions."""
        arn = "arn:aws:iam::123456789012:user/deploy-bot"
        assert _normalize_role_name(arn) == "user/deploy-bot"

    def test_unknown_arn_returns_full_arn(self) -> None:
        """Unknown ARN format returns the full ARN as fallback."""
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-func"
        assert _normalize_role_name(arn) == arn


class TestCloudTrailMatchingWithNormalization:
    """End-to-end test: CloudTrail events with STS ARNs match IAM principal ARNs."""

    def test_sts_events_match_iam_principals(self) -> None:
        """Events with STS assumed-role ARNs correctly match IAM role ARNs."""
        # Feature: cloudtrail-resource-filter, ARN normalization
        iam_role_arn = "arn:aws:iam::724419084136:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_Admin_abc123"
        sts_session_arn = "arn:aws:sts::724419084136:assumed-role/AWSReservedSSO_Admin_abc123/user@example.com"

        # Build events with STS ARNs (as CloudTrail actually records them)
        events = [{
            "EventTime": datetime(2025, 6, 15, 10, 30, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({"userIdentity": {"arn": sts_session_arn}}),
            "Resources": [{"ResourceName": _SECRET_ARN}],
            "EventName": "GetSecretValue",
        }]

        with patch("secrets_audit.cloudtrail._fetch_events", return_value=events):
            result = get_last_accessed(
                session=None,
                secret_arn=_SECRET_ARN,
                principal_arns=[iam_role_arn],
            )

        assert result[iam_role_arn] == datetime(2025, 6, 15, 10, 30, tzinfo=timezone.utc), (
            f"Expected timestamp match, got: {result[iam_role_arn]}"
        )

    def test_multiple_sessions_same_role_picks_latest(self) -> None:
        """Multiple STS sessions for the same role → latest timestamp wins."""
        iam_arn = "arn:aws:iam::123456789012:role/my-role"

        events = [
            {
                "EventTime": datetime(2025, 6, 10, tzinfo=timezone.utc),
                "CloudTrailEvent": json.dumps({"userIdentity": {"arn": "arn:aws:sts::123456789012:assumed-role/my-role/session-1"}}),
                "Resources": [{"ResourceName": _SECRET_ARN}],
                "EventName": "GetSecretValue",
            },
            {
                "EventTime": datetime(2025, 6, 20, tzinfo=timezone.utc),
                "CloudTrailEvent": json.dumps({"userIdentity": {"arn": "arn:aws:sts::123456789012:assumed-role/my-role/session-2"}}),
                "Resources": [{"ResourceName": _SECRET_ARN}],
                "EventName": "GetSecretValue",
            },
        ]

        with patch("secrets_audit.cloudtrail._fetch_events", return_value=events):
            result = get_last_accessed(
                session=None,
                secret_arn=_SECRET_ARN,
                principal_arns=[iam_arn],
            )

        assert result[iam_arn] == datetime(2025, 6, 20, tzinfo=timezone.utc)

    def test_unmatched_principal_gets_no_recent_access(self) -> None:
        """A principal with no matching CloudTrail events gets NO_RECENT_ACCESS."""
        iam_arn = "arn:aws:iam::123456789012:role/never-accessed"

        events = [{
            "EventTime": datetime(2025, 6, 15, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({"userIdentity": {"arn": "arn:aws:sts::123456789012:assumed-role/other-role/session"}}),
            "Resources": [{"ResourceName": _SECRET_ARN}],
            "EventName": "GetSecretValue",
        }]

        with patch("secrets_audit.cloudtrail._fetch_events", return_value=events):
            result = get_last_accessed(
                session=None,
                secret_arn=_SECRET_ARN,
                principal_arns=[iam_arn],
            )

        assert result[iam_arn] == NO_RECENT_ACCESS


# ---------------------------------------------------------------------------
# Test Gap 5: _normalize_role_name with EKS OIDC session name
# ---------------------------------------------------------------------------


class TestARNNormalizationEKSOIDC(TestARNNormalization):
    """Additional ARN normalization tests for EKS OIDC assumed-role sessions."""

    def test_sts_eks_oidc_session_extracts_role_name(self) -> None:
        """EKS OIDC assumed-role ARN with serviceaccount session → bare role name."""
        arn = "arn:aws:sts::123456789012:assumed-role/eks-pod-role/system:serviceaccount:default:my-sa"
        assert _normalize_role_name(arn) == "eks-pod-role"


class TestCloudTrailMatchingEKSOIDC(TestCloudTrailMatchingWithNormalization):
    """Additional CloudTrail matching tests for EKS OIDC sessions."""

    def test_eks_oidc_events_match_iam_principals(self) -> None:
        """EKS OIDC assumed-role session ARNs match IAM role ARNs."""
        iam_arn = "arn:aws:iam::123456789012:role/eks-pod-role"
        sts_arn = "arn:aws:sts::123456789012:assumed-role/eks-pod-role/system:serviceaccount:default:my-sa"

        events = [{
            "EventTime": datetime(2025, 6, 15, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({"userIdentity": {"arn": sts_arn}}),
            "Resources": [{"ResourceName": _SECRET_ARN}],
            "EventName": "GetSecretValue",
        }]

        with patch("secrets_audit.cloudtrail._fetch_events", return_value=events):
            result = get_last_accessed(
                session=None,
                secret_arn=_SECRET_ARN,
                principal_arns=[iam_arn],
            )

        assert result[iam_arn] == datetime(2025, 6, 15, tzinfo=timezone.utc)
