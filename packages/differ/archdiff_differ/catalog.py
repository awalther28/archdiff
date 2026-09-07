"""Bundled IAM action catalog used to expand wildcard actions.

LIMIT: only five services are covered -- s3, sts, iam, kms, secretsmanager.
This is a deliberate v1 boundary, not an oversight: the catalog is a static
snapshot, needs no network, and covers the services that matter most for
privilege-escalation analysis.  Wildcards in any other service (``ec2:*``,
``lambda:Get*``) are kept as opaque tokens, matched only by exact string or by
glob against *other tokens*, and surfaced as ``unexpandable`` on the capability
so a reader knows the expansion was not performed.

A bare ``*`` expands to every action in the catalog *and* stays as the token
``*`` so it still matches services we do not know.
"""
from fnmatch import fnmatchcase
from typing import Dict, FrozenSet, Iterable, List, Set, Tuple

CATALOG_VERSION = "bundled-2026-09"

CATALOG: Dict[str, Tuple[str, ...]] = {
    "sts": (
        "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity", "AssumeRoot",
        "DecodeAuthorizationMessage", "GetAccessKeyInfo", "GetCallerIdentity",
        "GetFederationToken", "GetServiceBearerToken", "GetSessionToken", "SetContext",
        "SetSourceIdentity", "TagSession",
    ),
    "kms": (
        "CancelKeyDeletion", "ConnectCustomKeyStore", "CreateAlias", "CreateCustomKeyStore",
        "CreateGrant", "CreateKey", "Decrypt", "DeleteAlias", "DeleteCustomKeyStore",
        "DeleteImportedKeyMaterial", "DeriveSharedSecret", "DescribeCustomKeyStores",
        "DescribeKey", "DisableKey", "DisableKeyRotation", "DisconnectCustomKeyStore",
        "EnableKey", "EnableKeyRotation", "Encrypt", "GenerateDataKey", "GenerateDataKeyPair",
        "GenerateDataKeyPairWithoutPlaintext", "GenerateDataKeyWithoutPlaintext",
        "GenerateMac", "GenerateRandom", "GetKeyPolicy", "GetKeyRotationStatus",
        "GetParametersForImport", "GetPublicKey", "ImportKeyMaterial", "ListAliases",
        "ListGrants", "ListKeyPolicies", "ListKeyRotations", "ListKeys", "ListResourceTags",
        "ListRetirableGrants", "PutKeyPolicy", "ReEncryptFrom", "ReEncryptTo", "ReplicateKey",
        "RetireGrant", "RevokeGrant", "RotateKeyOnDemand", "ScheduleKeyDeletion", "Sign",
        "SynchronizeMultiRegionKey", "TagResource", "UntagResource", "UpdateAlias",
        "UpdateCustomKeyStore", "UpdateKeyDescription", "UpdatePrimaryRegion", "Verify",
        "VerifyMac",
    ),
    "secretsmanager": (
        "BatchGetSecretValue", "CancelRotateSecret", "CreateSecret", "DeleteResourcePolicy",
        "DeleteSecret", "DescribeSecret", "GetRandomPassword", "GetResourcePolicy",
        "GetSecretValue", "ListSecretVersionIds", "ListSecrets", "PutResourcePolicy",
        "PutSecretValue", "RemoveRegionsFromReplication", "ReplicateSecretToRegions",
        "RestoreSecret", "RotateSecret", "StopReplicationToReplica", "TagResource",
        "UntagResource", "UpdateSecret", "UpdateSecretVersionStage", "ValidateResourcePolicy",
    ),
    "iam": (
        "AddClientIDToOpenIDConnectProvider", "AddRoleToInstanceProfile", "AddUserToGroup",
        "AttachGroupPolicy", "AttachRolePolicy", "AttachUserPolicy", "ChangePassword",
        "CreateAccessKey", "CreateAccountAlias", "CreateGroup", "CreateInstanceProfile",
        "CreateLoginProfile", "CreateOpenIDConnectProvider", "CreatePolicy",
        "CreatePolicyVersion", "CreateRole", "CreateSAMLProvider", "CreateServiceLinkedRole",
        "CreateServiceSpecificCredential", "CreateUser", "CreateVirtualMFADevice",
        "DeactivateMFADevice", "DeleteAccessKey", "DeleteAccountAlias",
        "DeleteAccountPasswordPolicy", "DeleteGroup", "DeleteGroupPolicy",
        "DeleteInstanceProfile", "DeleteLoginProfile", "DeleteOpenIDConnectProvider",
        "DeletePolicy", "DeletePolicyVersion", "DeleteRole", "DeleteRolePermissionsBoundary",
        "DeleteRolePolicy", "DeleteSAMLProvider", "DeleteSSHPublicKey",
        "DeleteServerCertificate", "DeleteServiceLinkedRole",
        "DeleteServiceSpecificCredential", "DeleteSigningCertificate", "DeleteUser",
        "DeleteUserPermissionsBoundary", "DeleteUserPolicy", "DeleteVirtualMFADevice",
        "DetachGroupPolicy", "DetachRolePolicy", "DetachUserPolicy", "EnableMFADevice",
        "GenerateCredentialReport", "GenerateOrganizationsAccessReport",
        "GenerateServiceLastAccessedDetails", "GetAccessKeyLastUsed",
        "GetAccountAuthorizationDetails", "GetAccountEmailAddress", "GetAccountName",
        "GetAccountPasswordPolicy", "GetAccountSummary", "GetContextKeysForCustomPolicy",
        "GetContextKeysForPrincipalPolicy", "GetCredentialReport", "GetGroup",
        "GetGroupPolicy", "GetInstanceProfile", "GetLoginProfile", "GetMFADevice",
        "GetOpenIDConnectProvider", "GetOrganizationsAccessReport", "GetPolicy",
        "GetPolicyVersion", "GetRole", "GetRolePolicy", "GetSAMLProvider", "GetSSHPublicKey",
        "GetServerCertificate", "GetServiceLastAccessedDetails",
        "GetServiceLastAccessedDetailsWithEntities", "GetServiceLinkedRoleDeletionStatus",
        "GetUser", "GetUserPolicy", "ListAccessKeys", "ListAccountAliases",
        "ListAttachedGroupPolicies", "ListAttachedRolePolicies", "ListAttachedUserPolicies",
        "ListEntitiesForPolicy", "ListGroupPolicies", "ListGroups", "ListGroupsForUser",
        "ListInstanceProfileTags", "ListInstanceProfiles", "ListInstanceProfilesForRole",
        "ListMFADeviceTags", "ListMFADevices", "ListOpenIDConnectProviderTags",
        "ListOpenIDConnectProviders", "ListPolicies", "ListPoliciesGrantingServiceAccess",
        "ListPolicyTags", "ListPolicyVersions", "ListRolePolicies", "ListRoleTags",
        "ListRoles", "ListSAMLProviderTags", "ListSAMLProviders", "ListSSHPublicKeys",
        "ListServerCertificateTags", "ListServerCertificates",
        "ListServiceSpecificCredentials", "ListSigningCertificates", "ListUserPolicies",
        "ListUserTags", "ListUsers", "ListVirtualMFADevices", "PassRole", "PutGroupPolicy",
        "PutRolePermissionsBoundary", "PutRolePolicy", "PutUserPermissionsBoundary",
        "PutUserPolicy", "RemoveClientIDFromOpenIDConnectProvider",
        "RemoveRoleFromInstanceProfile", "RemoveUserFromGroup",
        "ResetServiceSpecificCredential", "ResyncMFADevice", "SetDefaultPolicyVersion",
        "SetSecurityTokenServicePreferences", "SimulateCustomPolicy",
        "SimulatePrincipalPolicy", "TagInstanceProfile", "TagMFADevice",
        "TagOpenIDConnectProvider", "TagPolicy", "TagRole", "TagSAMLProvider",
        "TagServerCertificate", "TagUser", "UntagInstanceProfile", "UntagMFADevice",
        "UntagOpenIDConnectProvider", "UntagPolicy", "UntagRole", "UntagSAMLProvider",
        "UntagServerCertificate", "UntagUser", "UpdateAccessKey",
        "UpdateAccountPasswordPolicy", "UpdateAssumeRolePolicy", "UpdateGroup",
        "UpdateLoginProfile", "UpdateOpenIDConnectProviderThumbprint", "UpdateRole",
        "UpdateRoleDescription", "UpdateSAMLProvider", "UpdateSSHPublicKey",
        "UpdateServerCertificate", "UpdateServiceSpecificCredential",
        "UpdateSigningCertificate", "UpdateUser", "UploadSSHPublicKey",
        "UploadServerCertificate", "UploadSigningCertificate",
    ),
    "s3": (
        "AbortMultipartUpload", "BypassGovernanceRetention", "CreateAccessPoint",
        "CreateAccessPointForObjectLambda", "CreateBucket", "CreateJob",
        "CreateMultiRegionAccessPoint", "DeleteAccessPoint",
        "DeleteAccessPointForObjectLambda", "DeleteAccessPointPolicy",
        "DeleteAccessPointPolicyForObjectLambda", "DeleteBucket",
        "DeleteBucketOwnershipControls", "DeleteBucketPolicy", "DeleteBucketWebsite",
        "DeleteJobTagging", "DeleteMultiRegionAccessPoint", "DeleteObject",
        "DeleteObjectTagging", "DeleteObjectVersion", "DeleteObjectVersionTagging",
        "DeleteStorageLensConfiguration", "DeleteStorageLensConfigurationTagging",
        "DescribeJob", "DescribeMultiRegionAccessPointOperation",
        "GetAccelerateConfiguration", "GetAccessPoint",
        "GetAccessPointConfigurationForObjectLambda", "GetAccessPointForObjectLambda",
        "GetAccessPointPolicy", "GetAccessPointPolicyForObjectLambda",
        "GetAccessPointPolicyStatus", "GetAccessPointPolicyStatusForObjectLambda",
        "GetAccountPublicAccessBlock", "GetAnalyticsConfiguration", "GetBucketAcl",
        "GetBucketCORS", "GetBucketLocation", "GetBucketLogging", "GetBucketNotification",
        "GetBucketObjectLockConfiguration", "GetBucketOwnershipControls", "GetBucketPolicy",
        "GetBucketPolicyStatus", "GetBucketPublicAccessBlock", "GetBucketRequestPayment",
        "GetBucketTagging", "GetBucketVersioning", "GetBucketWebsite",
        "GetEncryptionConfiguration", "GetIntelligentTieringConfiguration",
        "GetInventoryConfiguration", "GetJobTagging", "GetLifecycleConfiguration",
        "GetMetricsConfiguration", "GetMultiRegionAccessPoint",
        "GetMultiRegionAccessPointPolicy", "GetMultiRegionAccessPointPolicyStatus",
        "GetObject", "GetObjectAcl", "GetObjectAttributes", "GetObjectLegalHold",
        "GetObjectRetention", "GetObjectTagging", "GetObjectTorrent", "GetObjectVersion",
        "GetObjectVersionAcl", "GetObjectVersionAttributes", "GetObjectVersionForReplication",
        "GetObjectVersionTagging", "GetObjectVersionTorrent", "GetReplicationConfiguration",
        "GetStorageLensConfiguration", "GetStorageLensConfigurationTagging",
        "GetStorageLensDashboard", "InitiateReplication", "ListAccessPoints",
        "ListAccessPointsForObjectLambda", "ListAllMyBuckets", "ListBucket",
        "ListBucketMultipartUploads", "ListBucketVersions", "ListJobs",
        "ListMultiRegionAccessPoints", "ListMultipartUploadParts",
        "ListStorageLensConfigurations", "ObjectOwnerOverrideToBucketOwner",
        "PutAccelerateConfiguration", "PutAccessPointConfigurationForObjectLambda",
        "PutAccessPointPolicy", "PutAccessPointPolicyForObjectLambda",
        "PutAccessPointPublicAccessBlock", "PutAccountPublicAccessBlock",
        "PutAnalyticsConfiguration", "PutBucketAcl", "PutBucketCORS", "PutBucketLogging",
        "PutBucketNotification", "PutBucketObjectLockConfiguration",
        "PutBucketOwnershipControls", "PutBucketPolicy", "PutBucketPublicAccessBlock",
        "PutBucketRequestPayment", "PutBucketTagging", "PutBucketVersioning",
        "PutBucketWebsite", "PutEncryptionConfiguration",
        "PutIntelligentTieringConfiguration", "PutInventoryConfiguration", "PutJobTagging",
        "PutLifecycleConfiguration", "PutMetricsConfiguration",
        "PutMultiRegionAccessPointPolicy", "PutObject", "PutObjectAcl", "PutObjectLegalHold",
        "PutObjectRetention", "PutObjectTagging", "PutObjectVersionAcl",
        "PutObjectVersionTagging", "PutReplicationConfiguration",
        "PutStorageLensConfiguration", "PutStorageLensConfigurationTagging",
        "ReplicateDelete", "ReplicateObject", "ReplicateTags", "RestoreObject",
        "UpdateJobPriority", "UpdateJobStatus",
    ),
}

SERVICES: FrozenSet[str] = frozenset(CATALOG)
_ALL_ACTIONS: Tuple[str, ...] = tuple(sorted(f"{svc}:{a}" for svc, acts in CATALOG.items()
                                             for a in acts))
_LOWER: Dict[str, str] = {a.lower(): a for a in _ALL_ACTIONS}


def is_wildcard(action: str) -> bool:
    return "*" in action or "?" in action


def canonical_action(action: str) -> str:
    """Normalise case for actions in the catalog (IAM matches actions
    case-insensitively).  Unknown actions are returned unchanged."""
    return _LOWER.get(action.lower(), action)


def expand_action(pattern: str) -> Tuple[List[str], bool]:
    """Expand one action pattern against the catalog.

    Returns ``(tokens, expandable)``.  For a catalog service the tokens are the
    concrete matching actions.  For ``*`` the tokens are the whole catalog plus
    the literal ``*``.  For a wildcard in an unknown service the single token is
    the pattern itself and ``expandable`` is False.
    """
    if not is_wildcard(pattern):
        return [canonical_action(pattern)], True
    if pattern == "*":
        return list(_ALL_ACTIONS) + ["*"], True
    svc, _, _ = pattern.partition(":")
    svc_l = svc.lower()
    if svc_l in CATALOG and "*" not in svc and "?" not in svc:
        pat = pattern.lower()
        matched = [a for a in _ALL_ACTIONS if a.startswith(svc_l + ":") and
                   fnmatchcase(a.lower(), pat)]
        return matched, True
    if "*" in svc or "?" in svc:
        # e.g. "s*:Get*" -- match across the catalog, keep the token too
        pat = pattern.lower()
        matched = [a for a in _ALL_ACTIONS if fnmatchcase(a.lower(), pat)]
        return matched + [pattern], True
    return [pattern], False


def expand_actions(patterns: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Expand a statement's action list.  Returns (sorted unique tokens,
    sorted list of patterns that could not be expanded)."""
    tokens: Set[str] = set()
    unexpandable: List[str] = []
    for p in patterns:
        t, ok = expand_action(p)
        tokens.update(t)
        if not ok:
            unexpandable.append(p)
    return sorted(tokens), sorted(set(unexpandable))


def action_matches(token: str, pattern: str) -> bool:
    """Does an action token fall under an (possibly wildcard) action pattern?"""
    return fnmatchcase(token.lower(), pattern.lower())
