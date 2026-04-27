"""Integration tests using moto mocks for the full secrets-audit pipeline.

Tests the CLI end-to-end with mocked AWS services to verify:
- Full pipeline with mixed principal types (Task 13.1)
- Cross-account failure graceful degradation (Task 13.2)
- CloudTrail unavailable (Task 13.3)
- Empty principals (Task 13.4)

**Security invariant**: these tests never call ``GetSecretValue``.
All AWS interactions are mocked via moto — no real credentials are used.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import boto3
import pytest
from click.testing import CliRunner
from moto import mock_aws

from secrets_audit.cli import main
from secrets_audit.resolver import SimulationResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"  # nosemgrep: generic.secrets.security.detected-aws-account-id
SECRET_NAME = "rds/prod-db-west/app_user"  # nosec B105


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_secret(session: boto3.Session) -> str:
    """Create a test secret and return its ARN."""
    sm = session.client("secretsmanager", region_name=REGION)
    resp = sm.create_secret(
        Name=SECRET_NAME,
        # We store a dummy SecretString for moto — the tool never reads it.
        SecretString="PLACEHOLDER_NOT_USED",  # nosec B106
    )
    return resp["ARN"]


def _setup_iam_user(session: boto3.Session, name: str) -> str:
    """Create an IAM user and return its ARN."""
    iam = session.client("iam", region_name=REGION)
    resp = iam.create_user(UserName=name)
    return resp["User"]["Arn"]


def _setup_iam_role(
    session: boto3.Session,
    name: str,
    trust_policy: dict,
    path: str = "/",
) -> str:
    """Create an IAM role with a given trust policy and return its ARN."""
    iam = session.client("iam", region_name=REGION)
    resp = iam.create_role(
        RoleName=name,
        Path=path,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )
    return resp["Role"]["Arn"]


def _plain_trust_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _sso_trust_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sso.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _eks_trust_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": (
                        f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/"
                        f"oidc.eks.{REGION}.amazonaws.com/id/ABCDEF1234567890"
                    )
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Task 13.1: Full pipeline with mixed principal types
# ---------------------------------------------------------------------------


class TestFullPipelineMixedPrincipals:
    """Integration test: IC role, EKS role, and plain IAM user.

    Moto doesn't support SimulatePrincipalPolicy, so we patch that to
    return controlled results while letting all other AWS calls go through
    moto's real mock implementations.
    """

    @mock_aws
    def test_mixed_principals_table_output(self) -> None:
        """Full pipeline produces correct classifications in table output."""
        session = boto3.Session(region_name=REGION)

        # Setup AWS resources
        secret_arn = _setup_secret(session)
        user_arn = _setup_iam_user(session, "plain-user")
        sso_role_arn = _setup_iam_role(
            session,
            "AWSReservedSSO_ReadOnlyAccess_abcdef123456",
            _sso_trust_policy(),
            path=f"/aws-reserved/sso.amazonaws.com/{REGION}/",
        )
        eks_role_arn = _setup_iam_role(
            session,
            "eks-pod-role",
            _eks_trust_policy(),
        )

        # Build simulated access results
        from secrets_audit.models import AccessLevel, PrincipalAccess, PrincipalType

        sim_results = [
            PrincipalAccess(
                principal_type=PrincipalType.IAM_USER,
                principal_arn=user_arn,
                principal_name="plain-user",
                access_level=AccessLevel.READ,
                allowed_actions=["secretsmanager:GetSecretValue"],
                policy_source="identity_policy",
            ),
            PrincipalAccess(
                principal_type=PrincipalType.IAM_ROLE,
                principal_arn=sso_role_arn,
                principal_name="AWSReservedSSO_ReadOnlyAccess_abcdef123456",
                access_level=AccessLevel.READ,
                allowed_actions=["secretsmanager:GetSecretValue"],
                policy_source="identity_policy",
            ),
            PrincipalAccess(
                principal_type=PrincipalType.IAM_ROLE,
                principal_arn=eks_role_arn,
                principal_name="eks-pod-role",
                access_level=AccessLevel.READ_WRITE,
                allowed_actions=[
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                ],
                policy_source="identity_policy",
            ),
        ]

        runner = CliRunner(mix_stderr=False)
        with (
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=sim_results)),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
        ):
            result = runner.invoke(
                main,
                ["--secret", SECRET_NAME, "--output", "table"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        output = result.output

        # Verify metadata header
        assert SECRET_NAME in output
        assert "secrets-audit v" in output

        # Verify principal classifications
        assert "plain-user" in output
        assert "AWSReservedSSO_ReadOnlyAccess_abcdef123456" in output
        assert "eks-pod-role" in output

    @mock_aws
    def test_mixed_principals_json_output(self) -> None:
        """Full pipeline produces valid JSON with correct structure."""
        session = boto3.Session(region_name=REGION)

        secret_arn = _setup_secret(session)
        user_arn = _setup_iam_user(session, "json-user")

        from secrets_audit.models import AccessLevel, PrincipalAccess, PrincipalType

        sim_results = [
            PrincipalAccess(
                principal_type=PrincipalType.IAM_USER,
                principal_arn=user_arn,
                principal_name="json-user",
                access_level=AccessLevel.ADMIN,
                allowed_actions=["secretsmanager:*"],
                policy_source="identity_policy",
            ),
        ]

        runner = CliRunner(mix_stderr=False)
        with (
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=sim_results)),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
        ):
            result = runner.invoke(
                main,
                ["--secret", SECRET_NAME, "--output", "json"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        data = json.loads(result.output)

        # Verify structure
        assert data["secret_name"] == SECRET_NAME
        assert "generated_at" in data
        assert "generated_by" in data
        assert "tool_version" in data
        assert len(data["principals"]) == 1
        assert data["principals"][0]["principal_name"] == "json-user"
        assert data["principals"][0]["access_level"] == "Admin"


# ---------------------------------------------------------------------------
# Task 13.2: Cross-account failure graceful degradation
# ---------------------------------------------------------------------------


class TestCrossAccountFailure:
    """Verify partial report when cross-account AssumeRole fails."""

    @mock_aws
    def test_cross_account_failure_shows_permission_set_only(self) -> None:
        """When AssumeRole fails, IC roles show permission set name with warning."""
        session = boto3.Session(region_name=REGION)

        _setup_secret(session)
        sso_role_arn = _setup_iam_role(
            session,
            "AWSReservedSSO_AdminAccess_abcdef123456",
            _sso_trust_policy(),
            path=f"/aws-reserved/sso.amazonaws.com/{REGION}/",
        )

        from secrets_audit.models import AccessLevel, PrincipalAccess, PrincipalType

        sim_results = [
            PrincipalAccess(
                principal_type=PrincipalType.IAM_ROLE,
                principal_arn=sso_role_arn,
                principal_name="AWSReservedSSO_AdminAccess_abcdef123456",
                access_level=AccessLevel.ADMIN,
                allowed_actions=["secretsmanager:*"],
                policy_source="identity_policy",
            ),
        ]

        from secrets_audit.aws_clients import CrossAccountError

        runner = CliRunner(mix_stderr=False)
        with (
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=sim_results)),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
            patch(
                "secrets_audit.cli.create_cross_account_session",
                side_effect=CrossAccountError("Access denied"),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "--secret", SECRET_NAME,
                    "--output", "json",
                    "--master-account-id", "987654321098",
                    "--cross-account-role-arn",
                    "arn:aws:iam::987654321098:role/cross-account-role",
                    "--allow-partial",
                ],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        data = json.loads(result.output)

        # Should have a warning about cross-account failure
        assert len(data["warnings"]) >= 1
        assert any("assume" in w.lower() or "cross-account" in w.lower() for w in data["warnings"])

        # The IC role should still appear with partial resolution
        ic_principal = data["principals"][0]
        assert ic_principal["principal_name"] == "AWSReservedSSO_AdminAccess_abcdef123456"
        assert ic_principal.get("ic_partial") is True
        assert ic_principal.get("permission_set_name") == "AdminAccess"


# ---------------------------------------------------------------------------
# Task 13.3: CloudTrail unavailable
# ---------------------------------------------------------------------------


class TestCloudTrailUnavailable:
    """Verify graceful degradation when CloudTrail is inaccessible."""

    @mock_aws
    def test_cloudtrail_unavailable_shows_unknown(self) -> None:
        """When CloudTrail raises AccessDenied, last_accessed shows 'Unknown'."""
        session = boto3.Session(region_name=REGION)

        _setup_secret(session)
        user_arn = _setup_iam_user(session, "ct-test-user")

        from secrets_audit.cloudtrail import CLOUDTRAIL_UNAVAILABLE
        from secrets_audit.models import AccessLevel, PrincipalAccess, PrincipalType

        sim_results = [
            PrincipalAccess(
                principal_type=PrincipalType.IAM_USER,
                principal_arn=user_arn,
                principal_name="ct-test-user",
                access_level=AccessLevel.READ,
                allowed_actions=["secretsmanager:GetSecretValue"],
                policy_source="identity_policy",
            ),
        ]

        # Make get_last_accessed return the "unavailable" status
        ct_result = {user_arn: CLOUDTRAIL_UNAVAILABLE}

        runner = CliRunner(mix_stderr=False)
        with (
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=sim_results)),
            patch("secrets_audit.cli.get_last_accessed", return_value=ct_result),
        ):
            result = runner.invoke(
                main,
                ["--secret", SECRET_NAME, "--output", "json", "--last-accessed"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        data = json.loads(result.output)

        assert len(data["principals"]) == 1
        assert data["principals"][0]["last_accessed"] == CLOUDTRAIL_UNAVAILABLE


# ---------------------------------------------------------------------------
# Task 13.4: Empty principals
# ---------------------------------------------------------------------------


class TestEmptyPrincipals:
    """Verify output when no IAM principals have access."""

    @mock_aws
    def test_empty_principals_table(self) -> None:
        """Table output shows 'No IAM principals' message."""
        session = boto3.Session(region_name=REGION)
        _setup_secret(session)

        runner = CliRunner(mix_stderr=False)
        with (
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
        ):
            result = runner.invoke(
                main,
                ["--secret", SECRET_NAME, "--output", "table"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        assert "No IAM principals have access to this secret" in result.output

    @mock_aws
    def test_empty_principals_json(self) -> None:
        """JSON output has empty principals list."""
        session = boto3.Session(region_name=REGION)
        _setup_secret(session)

        runner = CliRunner(mix_stderr=False)
        with (
            patch("secrets_audit.cli.simulate_principal_access", return_value=SimulationResult(principals=[])),
            patch("secrets_audit.cli.get_last_accessed", return_value={}),
        ):
            result = runner.invoke(
                main,
                ["--secret", SECRET_NAME, "--output", "json"],
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        data = json.loads(result.output)
        assert data["principals"] == []
        assert data["secret_name"] == SECRET_NAME
