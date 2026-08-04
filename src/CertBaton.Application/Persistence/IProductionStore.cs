using CertBaton.Domain.Connections;
using CertBaton.Domain.Deployments;
using CertBaton.Domain.Operations;
using CertBaton.Domain.Scheduling;
using CertBaton.Domain.Targets;

namespace CertBaton.Application.Persistence;

public interface IProductionStore
{
    void Initialize(DateTimeOffset initializedAtUtc);

    void SaveConnection(ConnectionProfile connectionProfile);

    void SaveTarget(CertificateTarget target);

    void SaveDeploymentPlan(DeploymentPlan deploymentPlan);

    void SaveRenewalPolicy(RenewalPolicy renewalPolicy);

    void SaveTargetIssuanceProfile(TargetIssuanceProfile issuanceProfile);

    void SaveEnrollment(TargetEnrollment enrollment);

    AcmeAccountRecord CreateOrGetAcmeAccount(AcmeAccountRecord account);

    ConnectionProfile? FindConnection(ConnectionId connectionId);

    CertificateTarget? FindTarget(TargetId targetId);

    IReadOnlyList<CertificateTarget> ListTargets(
        int maximumCount,
        TargetId? afterTargetId = null);

    DeploymentPlan? FindDeploymentPlan(DeploymentPlanId deploymentPlanId);

    DeploymentPlan? FindEnabledDeploymentPlan(TargetId targetId);

    RenewalPolicy? FindRenewalPolicy(RenewalPolicyId renewalPolicyId);

    RenewalPolicy? FindRenewalPolicyByTarget(TargetId targetId);

    RenewalPolicy? FindEnabledRenewalPolicy(TargetId targetId);

    TargetIssuanceProfile? FindTargetIssuanceProfile(TargetId targetId);

    AcmeAccountRecord? FindAcmeAccount(
        Uri directoryUri,
        string keySecretReference);

    AcmeAccountRecord? FindPreferredValidAcmeAccount(Uri directoryUri);

    AcmeAccountRecord UpdateAcmeAccountRegistration(
        AcmeAccountId accountId,
        AcmeAccountStatus expectedStatus,
        Uri? accountUri,
        AcmeAccountStatus newStatus,
        DateTimeOffset updatedAtUtc);

    RenewalOperation CreateOrGetOperation(RenewalOperation operation);

    RenewalOperation? TryStartOperation(
        OperationId operationId,
        Guid executionEpoch,
        DateTimeOffset startedAtUtc);

    RenewalOperation TransitionOwnedOperationStatus(
        OperationId operationId,
        Guid executionEpoch,
        OperationStatus expectedStatus,
        OperationStatus newStatus,
        DateTimeOffset updatedAtUtc,
        string? failureCode = null);

    OperationEvidence AppendOperationEvidence(
        OperationId operationId,
        OperationEvidenceKind kind,
        string? stage,
        OperationEvidenceOutcome outcome,
        DateTimeOffset recordedAtUtc,
        string code,
        string description);

    AuditEvent AppendAuditEvent(
        AuditEventId auditEventId,
        OperationId? operationId,
        TargetId? targetId,
        string actorSid,
        string eventType,
        DateTimeOffset occurredAtUtc,
        string code,
        string description);

    IReadOnlyList<AuditEvent> ReadAuditEvents(
        int maximumCount,
        long afterSequence = 0);

    OperationIntent CreateOrGetOperationIntent(OperationIntent operationIntent);

    OperationIntent? FindOperationIntent(OperationIntentId operationIntentId);

    OperationIntent? FindOperationIntentByIdempotencyKey(string idempotencyKey);

    IReadOnlyList<OperationIntent> ReadOperationIntents(OperationId operationId);

    OperationIntent TransitionOwnedOperationIntentStatus(
        OperationIntentId operationIntentId,
        Guid executionEpoch,
        OperationIntentStatus expectedStatus,
        OperationIntentStatus newStatus,
        DateTimeOffset transitionedAtUtc);

    CertificateArtifact CreateOrGetCertificateArtifact(
        CertificateArtifact certificateArtifact);

    CertificateArtifact? FindCertificateArtifact(OperationId operationId);

    CertificateArtifact TransitionCertificateArtifactStatus(
        CertificateArtifactId certificateArtifactId,
        CertificateArtifactStatus expectedStatus,
        CertificateArtifactStatus newStatus);

    RenewalOperation CompleteOwnedOperation(
        OperationId operationId,
        Guid executionEpoch,
        OperationStatus expectedStatus,
        OperationStatus terminalStatus,
        DateTimeOffset completedAtUtc,
        string? failureCode = null);

    RenewalOperation CompleteOwnedLiveRenewal(
        OperationId operationId,
        Guid executionEpoch,
        OperationStatus expectedStatus,
        OperationStatus terminalStatus,
        DateTimeOffset completedAtUtc,
        DateTimeOffset nextDueAtUtc,
        string? failureCode = null);

    RenewalOperation? FindOperation(OperationId operationId);

    IReadOnlyList<RenewalOperation> ListActiveOperations(int maximumCount);

    IReadOnlyList<OperationEvidence> ReadOperationEvidence(OperationId operationId);
}
