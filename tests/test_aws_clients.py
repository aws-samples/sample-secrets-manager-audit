"""Unit tests for secrets_audit.aws_clients."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import boto3
import botocore.exceptions
import pytest
from moto import mock_aws

from secrets_audit.aws_clients import (
    RETRY_CONFIG,
    CrossAccountError,
    create_cross_account_session,
    create_prod_session,
    get_caller_identity,
)


# ---------------------------------------------------------------------------
# create_prod_session
# ---------------------------------------------------------------------------


class TestCreateProdSession:
    """Tests for create_prod_session."""

    def test_returns_session(self) -> None:
        session = create_prod_session(region="us-west-2")
        assert isinstance(session, boto3.Session)

    def test_region_is_set(self) -> None:
        session = create_prod_session(region="eu-west-1")
        assert session.region_name == "eu-west-1"

    def test_none_region_accepted(self) -> None:
        session = create_prod_session(region=None)
        assert isinstance(session, boto3.Session)


# ---------------------------------------------------------------------------
# get_caller_identity
# ---------------------------------------------------------------------------


class TestGetCallerIdentity:
    """Tests for get_caller_identity."""

    @mock_aws
    def test_returns_arn(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        arn = get_caller_identity(session)
        # moto returns a deterministic ARN
        assert arn.startswith("arn:aws:")
        assert isinstance(arn, str)

    @mock_aws
    def test_returns_string_type(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        result = get_caller_identity(session)
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# create_cross_account_session
# ---------------------------------------------------------------------------


class TestCreateCrossAccountSession:
    """Tests for create_cross_account_session."""

    @mock_aws
    def test_successful_assumption(self) -> None:
        """AssumeRole succeeds and returns a usable session."""
        # Create the role that we'll assume
        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = (
            '{"Version":"2012-10-17","Statement":'
            '[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
        )
        iam.create_role(
            RoleName="cross-account-role",
            AssumeRolePolicyDocument=trust_policy,
        )

        prod_session = boto3.Session(region_name="us-east-1")
        role_arn = "arn:aws:iam::123456789012:role/cross-account-role"

        result = create_cross_account_session(
            prod_session, role_arn, region="us-west-2"
        )
        assert isinstance(result, boto3.Session)
        assert result.region_name == "us-west-2"

    @mock_aws
    def test_default_session_name(self) -> None:
        """Default session name is 'secrets-audit-session'."""
        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = (
            '{"Version":"2012-10-17","Statement":'
            '[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
        )
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=trust_policy,
        )

        prod_session = boto3.Session(region_name="us-east-1")
        role_arn = "arn:aws:iam::123456789012:role/test-role"

        # Should not raise — default session_name is used
        result = create_cross_account_session(prod_session, role_arn)
        assert isinstance(result, boto3.Session)

    @mock_aws
    def test_logs_info_on_success(self, caplog: pytest.LogCaptureFixture) -> None:
        """Successful assumption logs at INFO level."""
        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = (
            '{"Version":"2012-10-17","Statement":'
            '[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
        )
        iam.create_role(
            RoleName="log-role",
            AssumeRolePolicyDocument=trust_policy,
        )

        prod_session = boto3.Session(region_name="us-east-1")
        role_arn = "arn:aws:iam::123456789012:role/log-role"

        with caplog.at_level(logging.INFO, logger="secrets_audit.aws_clients"):
            create_cross_account_session(prod_session, role_arn)

        assert any("Cross-account assumption succeeded" in r.message for r in caplog.records)

    def test_client_error_raises_cross_account_error(self) -> None:
        """ClientError from AssumeRole is wrapped in CrossAccountError."""
        client_error = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
            "AssumeRole",
        )
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = client_error

        prod_session = MagicMock(spec=boto3.Session)
        prod_session.client.return_value = mock_sts

        bad_arn = "arn:aws:iam::999999999999:role/nonexistent-role"

        with pytest.raises(CrossAccountError, match="Unable to assume cross-account role"):
            create_cross_account_session(prod_session, bad_arn)

    def test_client_error_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """ClientError from AssumeRole logs at WARNING level."""
        client_error = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
            "AssumeRole",
        )
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = client_error

        prod_session = MagicMock(spec=boto3.Session)
        prod_session.client.return_value = mock_sts

        bad_arn = "arn:aws:iam::999999999999:role/nonexistent-role"

        with caplog.at_level(logging.WARNING, logger="secrets_audit.aws_clients"):
            with pytest.raises(CrossAccountError):
                create_cross_account_session(prod_session, bad_arn)

        assert any(
            "AssumeRole failed" in r.message and r.levelno == logging.WARNING
            for r in caplog.records
        )

    def test_cross_account_error_chains_original(self) -> None:
        """CrossAccountError preserves the original exception via __cause__."""
        client_error = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
            "AssumeRole",
        )
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = client_error

        prod_session = MagicMock(spec=boto3.Session)
        prod_session.client.return_value = mock_sts

        bad_arn = "arn:aws:iam::999999999999:role/nonexistent-role"

        with pytest.raises(CrossAccountError) as exc_info:
            create_cross_account_session(prod_session, bad_arn)

        assert exc_info.value.__cause__ is client_error

    def test_botocore_error_raises_cross_account_error(self) -> None:
        """BotoCoreError from AssumeRole is wrapped in CrossAccountError."""
        sdk_error = botocore.exceptions.EndpointConnectionError(endpoint_url="https://sts.us-east-1.amazonaws.com")
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = sdk_error

        prod_session = MagicMock(spec=boto3.Session)
        prod_session.client.return_value = mock_sts

        bad_arn = "arn:aws:iam::999999999999:role/some-role"

        with pytest.raises(CrossAccountError, match="Unable to assume cross-account role"):
            create_cross_account_session(prod_session, bad_arn)


# ---------------------------------------------------------------------------
# RETRY_CONFIG
# ---------------------------------------------------------------------------


class TestRetryConfig:
    """Tests for the module-level RETRY_CONFIG."""

    def test_max_attempts(self) -> None:
        # botocore may normalise max_attempts → total_max_attempts (initial + retries)
        retries = RETRY_CONFIG.retries
        if "max_attempts" in retries:
            assert retries["max_attempts"] == 5
        else:
            assert retries["total_max_attempts"] == 6  # 5 retries + 1 initial

    def test_adaptive_mode(self) -> None:
        assert RETRY_CONFIG.retries["mode"] == "adaptive"
