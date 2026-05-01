"""Domain models for secrets-audit.

All domain objects are Python dataclasses. Enums use (str, Enum) for clean
serialization.  No model in this module ever holds a secret value — only
metadata, principal information, and audit report structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, TypedDict


# --- Enums ---


class AccessLevel(str, Enum):
    """Classification of Secrets Manager permission scope."""

    READ = "Read"
    WRITE = "Write"
    READ_WRITE = "Read/Write"
    ADMIN = "Admin"


class PrincipalType(str, Enum):
    """Kind of IAM principal."""

    IAM_USER = "IAM User"
    IAM_ROLE = "IAM Role"
    IAM_GROUP = "IAM Group"


class PrincipalClassification(str, Enum):
    """How a principal was provisioned / what manages it."""

    IDENTITY_CENTER = "identity_center"
    EKS_SERVICE_ACCOUNT = "eks_service_account"
    PLAIN_IAM = "plain_iam"


# --- Core Data Models ---


@dataclass
class SecretMetadata:
    """Metadata from DescribeSecret.

    This dataclass MUST NEVER contain the secret value.  The tool never calls
    ``GetSecretValue`` — it only needs the name, ARN, and descriptive metadata
    returned by ``DescribeSecret``.
    """

    name: str
    arn: str
    description: str | None = None
    kms_key_id: str | None = None
    rotation_enabled: bool = False
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class SecretVersionInfo:
    """A single secret version's metadata from ListSecretVersionIds.

    This dataclass MUST NEVER contain the secret value. ListSecretVersionIds
    only returns version IDs, staging labels, and creation dates.
    """

    version_id: str
    staging_labels: list[str] = field(default_factory=list)
    created_date: datetime | None = None


@dataclass
class ICUserResolution:
    """A resolved Identity Center user."""

    user_id: str
    display_name: str | None = None
    email: str | None = None
    deleted: bool = False
    via_group: str | None = None  # None = direct assignment, else group name


@dataclass
class ICGroupResolution:
    """A resolved Identity Center group with optional member expansion."""

    group_id: str
    group_name: str
    members: list[ICUserResolution] = field(default_factory=list)
    total_member_count: int = 0


@dataclass
class IdentityCenterResolution:
    """Full IC resolution result for a permission set."""

    permission_set_name: str
    users: list[ICUserResolution] = field(default_factory=list)
    groups: list[ICGroupResolution] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    partial: bool = False  # True if cross-account resolution failed


@dataclass
class PrincipalAccess:
    """A single IAM principal's access to the target secret."""

    principal_type: PrincipalType
    principal_arn: str
    principal_name: str
    access_level: AccessLevel
    allowed_actions: list[str] = field(default_factory=list)
    classification: PrincipalClassification = PrincipalClassification.PLAIN_IAM
    # IC resolution (populated for IC-managed roles)
    ic_resolution: IdentityCenterResolution | None = None
    # EKS detail (populated for EKS service account roles)
    eks_detail: str | None = None  # e.g., "Assumed by EKS service account prod/app-sa"
    # CloudTrail enrichment
    last_accessed: datetime | str | None = None
    # Source: "identity_policy", "resource_policy", or "both"
    policy_source: str = "identity_policy"


@dataclass
class ReportMetadata:
    """Metadata block included in every report output."""

    secret_name: str
    secret_arn: str
    generated_at: str  # ISO 8601 with timezone offset
    generated_by: str  # Operator IAM ARN
    tool_version: str  # e.g., "secrets-audit v1.0.0"
    region: str | None = None  # Effective AWS region for the audit session


@dataclass
class AuditReport:
    """The complete audit report, ready for rendering."""

    metadata: ReportMetadata
    principals: list[PrincipalAccess] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    versions: list[SecretVersionInfo] = field(default_factory=list)


# --- GAAD Snapshot Types ---


class PrincipalSnapshot(TypedDict, total=False):
    """Pre-fetched policy data for a single IAM principal.

    Populated from ``GetAccountAuthorizationDetails`` (GAAD).
    ``inline_policies`` and ``managed_policies`` are always present (may be
    empty lists).  ``trust_policy`` and ``path`` are present only for roles.
    """

    inline_policies: list[dict[str, Any]]
    managed_policies: list[dict[str, Any]]
    trust_policy: dict[str, Any]
    path: str


AccountSnapshot = dict[str, PrincipalSnapshot]
