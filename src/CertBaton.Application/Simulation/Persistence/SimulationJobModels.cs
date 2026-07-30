using CertBaton.Domain.Renewals;

namespace CertBaton.Application.Simulation.Persistence;

public enum SimulationJobStatus
{
    Queued = 0,
    Running = 1,
    Succeeded = 2,
    Failed = 3,
    Cancelled = 4,
    Interrupted = 5,
}

public enum SimulationEvidenceKind
{
    Stage = 0,
    Terminal = 1,
    Recovery = 2,
}

public sealed record SimulationJobSnapshot(
    Guid JobId,
    string RequestKey,
    RenewalStage? FailureStage,
    SimulationJobStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    Guid? ExecutionEpoch,
    DateTimeOffset? ClaimedAtUtc,
    DateTimeOffset? CompletedAtUtc);

public sealed record SimulationJobDetails(
    SimulationJobSnapshot Job,
    IReadOnlyList<SimulationJobEvidence> Evidence);

public sealed record SimulationJobEvidence(
    Guid JobId,
    long Sequence,
    SimulationEvidenceKind Kind,
    RenewalStage? Stage,
    RenewalStageOutcome? Outcome,
    DateTimeOffset RecordedAtUtc,
    string Code,
    string Description);
