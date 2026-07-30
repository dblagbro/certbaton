using CertBaton.Application.Simulation.Persistence;
using CertBaton.Contracts;
using CertBaton.Domain.Renewals;

namespace CertBaton.Service;

public static class SimulationContractMapper
{
    public static SimulationRunSnapshot ToContract(SimulationJobDetails details)
    {
        ArgumentNullException.ThrowIfNull(details);

        var job = details.Job;
        var evidence = details.Evidence
            .Select(
                static item =>
                    new SimulationEvidenceSnapshot(
                        item.Sequence,
                        item.Stage.HasValue ? ToContract(item.Stage.Value) : null,
                        item.Outcome.HasValue ? ToContract(item.Outcome.Value) : null,
                        item.RecordedAtUtc,
                        item.Code,
                        item.Description))
            .ToArray();
        var lastStage = details.Evidence
            .Where(static item => item.Stage.HasValue)
            .Select(static item => item.Stage)
            .LastOrDefault();
        var isTerminal = job.Status is
            SimulationJobStatus.Succeeded or
            SimulationJobStatus.Failed or
            SimulationJobStatus.Cancelled or
            SimulationJobStatus.Interrupted;
        var currentStage = job.Status == SimulationJobStatus.Running
            ? FindCurrentStage(details.Evidence)
            : null;

        var result = new SimulationRunSnapshot(
            job.JobId,
            ToContract(job.Status),
            currentStage.HasValue ? ToContract(currentStage.Value) : null,
            isTerminal && lastStage.HasValue ? ToContract(lastStage.Value) : null,
            isTerminal ? ToContractOutcome(job.Status) : null,
            job.CreatedAtUtc,
            job.ClaimedAtUtc,
            job.CompletedAtUtc,
            Array.AsReadOnly(evidence));

        if (!result.TryValidate(out var error))
        {
            throw new InvalidOperationException(
                $"The persisted simulation could not be projected safely: {error}");
        }

        return result;
    }

    public static RenewalStage ParseStage(string value) =>
        value switch
        {
            SimulationContractValues.PreflightStage => RenewalStage.Preflight,
            SimulationContractValues.OrderStage => RenewalStage.Order,
            SimulationContractValues.ChallengeStage => RenewalStage.Challenge,
            SimulationContractValues.IssuanceStage => RenewalStage.Issuance,
            SimulationContractValues.DeploymentStage => RenewalStage.Deployment,
            SimulationContractValues.ActivationStage => RenewalStage.Activation,
            SimulationContractValues.VerificationStage => RenewalStage.Verification,
            SimulationContractValues.CleanupStage => RenewalStage.Cleanup,
            _ => throw new ArgumentOutOfRangeException(
                nameof(value),
                value,
                "The simulation stage is not supported."),
        };

    private static RenewalStage? FindCurrentStage(
        IReadOnlyList<SimulationJobEvidence> evidence)
    {
        var stages = evidence
            .Where(static item => item.Kind == SimulationEvidenceKind.Stage)
            .ToArray();
        if (stages.Length == 0)
        {
            return RenewalStage.Preflight;
        }

        var latestStage = stages[^1];
        if (latestStage.Outcome != RenewalStageOutcome.Succeeded)
        {
            return latestStage.Stage;
        }

        var completedIndex = Array.IndexOf(
            RenewalPipeline.Stages.ToArray(),
            latestStage.Stage);
        return completedIndex >= 0 &&
            completedIndex + 1 < RenewalPipeline.Stages.Count
                ? RenewalPipeline.Stages[completedIndex + 1]
                : latestStage.Stage;
    }

    private static string ToContract(RenewalStage stage) =>
        stage switch
        {
            RenewalStage.Preflight => SimulationContractValues.PreflightStage,
            RenewalStage.Order => SimulationContractValues.OrderStage,
            RenewalStage.Challenge => SimulationContractValues.ChallengeStage,
            RenewalStage.Issuance => SimulationContractValues.IssuanceStage,
            RenewalStage.Deployment => SimulationContractValues.DeploymentStage,
            RenewalStage.Activation => SimulationContractValues.ActivationStage,
            RenewalStage.Verification => SimulationContractValues.VerificationStage,
            RenewalStage.Cleanup => SimulationContractValues.CleanupStage,
            _ => throw new ArgumentOutOfRangeException(
                nameof(stage),
                stage,
                "The renewal stage is not supported by the IPC contract."),
        };

    private static string ToContract(RenewalStageOutcome outcome) =>
        outcome switch
        {
            RenewalStageOutcome.Succeeded =>
                SimulationContractValues.SucceededOutcome,
            RenewalStageOutcome.Failed =>
                SimulationContractValues.FailedOutcome,
            RenewalStageOutcome.Cancelled =>
                SimulationContractValues.CancelledOutcome,
            _ => throw new ArgumentOutOfRangeException(
                nameof(outcome),
                outcome,
                "The renewal outcome is not supported by the IPC contract."),
        };

    private static string ToContract(SimulationJobStatus status) =>
        status switch
        {
            SimulationJobStatus.Queued => SimulationContractValues.QueuedStatus,
            SimulationJobStatus.Running => SimulationContractValues.RunningStatus,
            SimulationJobStatus.Succeeded => SimulationContractValues.SucceededStatus,
            SimulationJobStatus.Failed => SimulationContractValues.FailedStatus,
            SimulationJobStatus.Cancelled => SimulationContractValues.CancelledStatus,
            SimulationJobStatus.Interrupted =>
                SimulationContractValues.InterruptedStatus,
            _ => throw new ArgumentOutOfRangeException(
                nameof(status),
                status,
                "The simulation job status is not supported by the IPC contract."),
        };

    private static string ToContractOutcome(SimulationJobStatus status) =>
        status switch
        {
            SimulationJobStatus.Succeeded =>
                SimulationContractValues.SucceededOutcome,
            SimulationJobStatus.Failed =>
                SimulationContractValues.FailedOutcome,
            SimulationJobStatus.Cancelled =>
                SimulationContractValues.CancelledOutcome,
            SimulationJobStatus.Interrupted =>
                SimulationContractValues.InterruptedOutcome,
            _ => throw new ArgumentOutOfRangeException(
                nameof(status),
                status,
                "A non-terminal job does not have a terminal outcome."),
        };
}
