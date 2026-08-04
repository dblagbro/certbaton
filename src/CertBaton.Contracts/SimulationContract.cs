using System.Collections.ObjectModel;

namespace CertBaton.Contracts;

public static class SimulationContractValues
{
    public const string PreflightStage = "preflight";
    public const string OrderStage = "order";
    public const string ChallengeStage = "challenge";
    public const string IssuanceStage = "issuance";
    public const string DeploymentStage = "deployment";
    public const string ActivationStage = "activation";
    public const string VerificationStage = "verification";
    public const string CleanupStage = "cleanup";

    public const string QueuedStatus = "queued";
    public const string RunningStatus = "running";
    public const string SucceededStatus = "succeeded";
    public const string FailedStatus = "failed";
    public const string CancelledStatus = "cancelled";
    public const string InterruptedStatus = "interrupted";

    public const string SucceededOutcome = "succeeded";
    public const string FailedOutcome = "failed";
    public const string CancelledOutcome = "cancelled";
    public const string InterruptedOutcome = "interrupted";

    public const int MaximumEvidenceRecords = 64;
    public const int MaximumEvidenceCodeLength = 128;
    public const int MaximumEvidenceDescriptionLength = 1024;

    private static readonly ReadOnlyCollection<string> stages =
        Array.AsReadOnly(
        [
            PreflightStage,
            OrderStage,
            ChallengeStage,
            IssuanceStage,
            DeploymentStage,
            ActivationStage,
            VerificationStage,
            CleanupStage,
        ]);

    public static IReadOnlyList<string> Stages => stages;

    public static bool IsStage(string value) =>
        value is
            PreflightStage or
            OrderStage or
            ChallengeStage or
            IssuanceStage or
            DeploymentStage or
            ActivationStage or
            VerificationStage or
            CleanupStage;

    public static bool IsStatus(string value) =>
        value is
            QueuedStatus or
            RunningStatus or
            SucceededStatus or
            FailedStatus or
            CancelledStatus or
            InterruptedStatus;

    public static bool IsOutcome(string value) =>
        value is
            SucceededOutcome or
            FailedOutcome or
            CancelledOutcome or
            InterruptedOutcome;
}

public sealed record SimulationRunSnapshot(
    Guid RunId,
    string Status,
    string? CurrentStage,
    string? TerminalStage,
    string? Outcome,
    DateTimeOffset RequestedAtUtc,
    DateTimeOffset? StartedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    IReadOnlyList<SimulationEvidenceSnapshot> Evidence)
{
    public bool TryValidate(out string? error)
    {
        if (RunId == Guid.Empty)
        {
            error = "A simulation run identifier cannot be empty.";
            return false;
        }

        if (!SimulationContractValues.IsStatus(Status))
        {
            error = "The simulation status is not a registered lower-case value.";
            return false;
        }

        if (CurrentStage is not null &&
            !SimulationContractValues.IsStage(CurrentStage))
        {
            error = "The simulation current stage is not a registered lower-case value.";
            return false;
        }

        if (TerminalStage is not null &&
            !SimulationContractValues.IsStage(TerminalStage))
        {
            error = "The simulation terminal stage is not a registered lower-case value.";
            return false;
        }

        if (Outcome is not null &&
            !SimulationContractValues.IsOutcome(Outcome))
        {
            error = "The simulation outcome is not a registered lower-case value.";
            return false;
        }

        if (!IsUtcTimestamp(RequestedAtUtc) ||
            StartedAtUtc is { } startedAtUtc && !IsUtcTimestamp(startedAtUtc) ||
            CompletedAtUtc is { } completedAtUtc && !IsUtcTimestamp(completedAtUtc))
        {
            error = "Simulation timestamps must be non-default UTC values.";
            return false;
        }

        if (StartedAtUtc < RequestedAtUtc ||
            CompletedAtUtc < (StartedAtUtc ?? RequestedAtUtc))
        {
            error = "Simulation timestamps are not in chronological order.";
            return false;
        }

        if (!TryValidateLifecycle(out error))
        {
            return false;
        }

        if (Evidence is null ||
            Evidence.Count > SimulationContractValues.MaximumEvidenceRecords)
        {
            error =
                $"Simulation evidence must contain no more than {SimulationContractValues.MaximumEvidenceRecords} records.";
            return false;
        }

        for (var index = 0; index < Evidence.Count; index++)
        {
            var item = Evidence[index];
            if (item is null)
            {
                error = "Simulation evidence cannot contain null records.";
                return false;
            }

            if (item.Sequence != index + 1)
            {
                error = "Simulation evidence sequence numbers must be contiguous and start at one.";
                return false;
            }

            if (!item.TryValidate(out error))
            {
                return false;
            }

            if (item.RecordedAtUtc < RequestedAtUtc ||
                CompletedAtUtc is { } completed &&
                item.RecordedAtUtc > completed)
            {
                error = "Simulation evidence timestamps fall outside the run window.";
                return false;
            }
        }

        if (Status == SimulationContractValues.SucceededStatus &&
            !ContainsCompleteSuccessfulPipeline())
        {
            error =
                "A succeeded simulation must contain successful evidence for all eight stages in order.";
            return false;
        }

        error = null;
        return true;
    }

    private bool TryValidateLifecycle(out string? error)
    {
        var isTerminal =
            Status is
                SimulationContractValues.SucceededStatus or
                SimulationContractValues.FailedStatus or
                SimulationContractValues.CancelledStatus or
                SimulationContractValues.InterruptedStatus;

        if (Status == SimulationContractValues.QueuedStatus &&
            (StartedAtUtc is not null ||
             CompletedAtUtc is not null ||
             CurrentStage is not null ||
             TerminalStage is not null ||
             Outcome is not null))
        {
            error = "A queued simulation cannot contain execution or terminal state.";
            return false;
        }

        if (Status == SimulationContractValues.RunningStatus &&
            (StartedAtUtc is null ||
             CompletedAtUtc is not null ||
             TerminalStage is not null ||
             Outcome is not null))
        {
            error = "A running simulation must contain only active execution state.";
            return false;
        }

        var terminalStageRequired =
            isTerminal &&
            Status != SimulationContractValues.InterruptedStatus;
        if (isTerminal &&
            (StartedAtUtc is null ||
             CompletedAtUtc is null ||
             CurrentStage is not null ||
             terminalStageRequired && TerminalStage is null ||
             Outcome != Status))
        {
            error = "A terminal simulation must contain matching terminal state.";
            return false;
        }

        error = null;
        return true;
    }

    private bool ContainsCompleteSuccessfulPipeline()
    {
        var expectedStageIndex = 0;
        foreach (var item in Evidence)
        {
            if (item.Stage is null)
            {
                continue;
            }

            if (expectedStageIndex >= SimulationContractValues.Stages.Count ||
                item.Stage != SimulationContractValues.Stages[expectedStageIndex] ||
                item.Outcome != SimulationContractValues.SucceededOutcome)
            {
                return false;
            }

            expectedStageIndex++;
        }

        return expectedStageIndex == SimulationContractValues.Stages.Count;
    }

    private static bool IsUtcTimestamp(DateTimeOffset value) =>
        value != default && value.Offset == TimeSpan.Zero;
}

public sealed record SimulationEvidenceSnapshot(
    long Sequence,
    string? Stage,
    string? Outcome,
    DateTimeOffset RecordedAtUtc,
    string Code,
    string Description)
{
    public bool TryValidate(out string? error)
    {
        if (Sequence <= 0)
        {
            error = "A simulation evidence sequence number must be positive.";
            return false;
        }

        if (Stage is not null && !SimulationContractValues.IsStage(Stage))
        {
            error = "A simulation evidence stage is not a registered lower-case value.";
            return false;
        }

        if (Outcome is not null &&
            !SimulationContractValues.IsOutcome(Outcome))
        {
            error = "A simulation evidence outcome is not a registered lower-case value.";
            return false;
        }

        if (RecordedAtUtc == default ||
            RecordedAtUtc.Offset != TimeSpan.Zero)
        {
            error = "A simulation evidence timestamp must be a non-default UTC value.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(Code) ||
            Code.Length > SimulationContractValues.MaximumEvidenceCodeLength)
        {
            error =
                $"A simulation evidence code must contain 1 to {SimulationContractValues.MaximumEvidenceCodeLength} characters.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(Description) ||
            Description.Length >
            SimulationContractValues.MaximumEvidenceDescriptionLength)
        {
            error =
                $"A simulation evidence description must contain 1 to {SimulationContractValues.MaximumEvidenceDescriptionLength} characters.";
            return false;
        }

        error = null;
        return true;
    }
}
