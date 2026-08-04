using CertBaton.Domain.Renewals;

namespace CertBaton.Application.Simulation.Persistence;

public interface ISimulationJobStore
{
    void Initialize(DateTimeOffset recoveredAtUtc);

    SimulationJobSnapshot CreateOrGetJob(
        Guid jobId,
        string requestKey,
        RenewalStage? failureStage,
        DateTimeOffset createdAtUtc);

    SimulationJobSnapshot? TryClaimNextQueuedJob(
        Guid executionEpoch,
        DateTimeOffset claimedAtUtc);

    void AppendStageEvidence(
        Guid jobId,
        Guid executionEpoch,
        RenewalStage stage,
        RenewalStageOutcome outcome,
        DateTimeOffset recordedAtUtc,
        string code,
        string description);

    void CompleteJob(
        Guid jobId,
        Guid executionEpoch,
        SimulationJobStatus terminalStatus,
        DateTimeOffset completedAtUtc,
        string code,
        string description);

    SimulationJobSnapshot? FindJob(Guid jobId);

    SimulationJobDetails? FindJobWithEvidence(Guid jobId);

    SimulationJobDetails? GetLatestJobWithEvidence();

    IReadOnlyList<SimulationJobEvidence> ReadEvidence(Guid jobId);
}
