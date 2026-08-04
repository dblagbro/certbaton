using System.Globalization;
using CertBaton.Domain.Targets;

namespace CertBaton.Domain.Operations;

public readonly record struct OperationId
{
    public OperationId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static OperationId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public enum OperationKind
{
    Renewal = 0,
}

public enum OperationStatus
{
    Queued = 0,
    Running = 1,
    Blocked = 2,
    RollbackRequired = 3,
    Succeeded = 4,
    Failed = 5,
    Cancelled = 6,
    Interrupted = 7,
}

public sealed record RenewalOperation
{
    public RenewalOperation(
        OperationId id,
        TargetId targetId,
        string requestKey,
        OperationStatus status,
        DateTimeOffset requestedAtUtc,
        DateTimeOffset updatedAtUtc,
        DateTimeOffset? startedAtUtc = null,
        DateTimeOffset? completedAtUtc = null,
        Guid? executionEpoch = null,
        string? failureCode = null)
    {
        ValidateOperationId(id, nameof(id));
        if (targetId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A target identifier cannot be empty.",
                nameof(targetId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(requestKey);
        if (requestKey.Length > 200 ||
            !string.Equals(requestKey, requestKey.Trim(), StringComparison.Ordinal) ||
            requestKey.Any(char.IsControl))
        {
            throw new ArgumentException(
                "An operation request key is invalid.",
                nameof(requestKey));
        }

        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(
                nameof(status),
                status,
                "The operation status is invalid.");
        }

        if (executionEpoch == Guid.Empty)
        {
            throw new ArgumentException(
                "An execution epoch cannot be empty.",
                nameof(executionEpoch));
        }

        if (failureCode is not null &&
            (string.IsNullOrWhiteSpace(failureCode) ||
                failureCode.Length > 128 ||
                !string.Equals(failureCode, failureCode.Trim(), StringComparison.Ordinal) ||
                failureCode.Any(char.IsControl)))
        {
            throw new ArgumentException(
                "An operation failure code is invalid.",
                nameof(failureCode));
        }

        var requested = requestedAtUtc.ToUniversalTime();
        var updated = updatedAtUtc.ToUniversalTime();
        var started = startedAtUtc?.ToUniversalTime();
        var completed = completedAtUtc?.ToUniversalTime();
        if (updated < requested ||
            started < requested ||
            completed < requested ||
            (started.HasValue && updated < started.Value) ||
            (started.HasValue && completed < started.Value))
        {
            throw new ArgumentException(
                "Operation timestamps cannot precede the request timestamp.");
        }

        var terminal = IsTerminal(status);
        if (terminal != completed.HasValue)
        {
            throw new ArgumentException(
                "Only terminal operations must have a completion timestamp.",
                nameof(completedAtUtc));
        }

        if (status == OperationStatus.Queued &&
            (started.HasValue || executionEpoch.HasValue))
        {
            throw new ArgumentException(
                "A queued operation cannot have execution ownership.",
                nameof(status));
        }

        Id = id;
        TargetId = targetId;
        RequestKey = requestKey;
        Kind = OperationKind.Renewal;
        Status = status;
        RequestedAtUtc = requested;
        UpdatedAtUtc = updated;
        StartedAtUtc = started;
        CompletedAtUtc = completed;
        ExecutionEpoch = executionEpoch;
        FailureCode = failureCode;
    }

    public OperationId Id { get; }

    public TargetId TargetId { get; }

    public string RequestKey { get; }

    public OperationKind Kind { get; }

    public OperationStatus Status { get; }

    public DateTimeOffset RequestedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; }

    public DateTimeOffset? StartedAtUtc { get; }

    public DateTimeOffset? CompletedAtUtc { get; }

    public Guid? ExecutionEpoch { get; }

    public string? FailureCode { get; }

    public static RenewalOperation CreateQueued(
        OperationId id,
        TargetId targetId,
        string requestKey,
        DateTimeOffset requestedAtUtc) =>
        new(
            id,
            targetId,
            requestKey,
            OperationStatus.Queued,
            requestedAtUtc,
            requestedAtUtc);

    public static bool IsTerminal(OperationStatus status) =>
        status is OperationStatus.Succeeded or
            OperationStatus.Failed or
            OperationStatus.Cancelled or
            OperationStatus.Interrupted;

    private static void ValidateOperationId(OperationId id, string parameterName)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation identifier cannot be empty.",
                parameterName);
        }
    }
}

public enum OperationEvidenceKind
{
    Stage = 0,
    Verification = 1,
    Cleanup = 2,
    Terminal = 3,
    Recovery = 4,
}

public enum OperationEvidenceOutcome
{
    Succeeded = 0,
    Failed = 1,
    Cancelled = 2,
}

public sealed record OperationEvidence
{
    public OperationEvidence(
        OperationId operationId,
        long sequence,
        OperationEvidenceKind kind,
        string? stage,
        OperationEvidenceOutcome outcome,
        DateTimeOffset recordedAtUtc,
        string code,
        string description)
    {
        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation identifier cannot be empty.",
                nameof(operationId));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome));
        }

        if ((kind == OperationEvidenceKind.Stage) != (stage is not null))
        {
            throw new ArgumentException(
                "Stage evidence requires a stage and other evidence cannot specify one.",
                nameof(stage));
        }

        if (stage is not null)
        {
            stage = ValidateText(stage, 64, nameof(stage));
        }

        OperationId = operationId;
        Sequence = sequence;
        Kind = kind;
        Stage = stage;
        Outcome = outcome;
        RecordedAtUtc = recordedAtUtc.ToUniversalTime();
        Code = ValidateText(code, 128, nameof(code));
        Description = ValidateText(description, 1_024, nameof(description));
    }

    public OperationId OperationId { get; }

    public long Sequence { get; }

    public OperationEvidenceKind Kind { get; }

    public string? Stage { get; }

    public OperationEvidenceOutcome Outcome { get; }

    public DateTimeOffset RecordedAtUtc { get; }

    public string Code { get; }

    public string Description { get; }

    private static string ValidateText(
        string value,
        int maximumLength,
        string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > maximumLength ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException("The evidence value is invalid.", parameterName);
        }

        return value;
    }
}

public readonly record struct OperationIntentId
{
    public OperationIntentId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation intent identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static OperationIntentId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public enum OperationIntentKind
{
    ChallengeWrite = 0,
    CertificateDeploy = 1,
    Activate = 2,
    Rollback = 3,
    RemotePrepare = 4,
    RemoteVerify = 5,
    Commit = 6,
    Abort = 7,
}

public enum OperationIntentStatus
{
    Planned = 0,
    Applied = 1,
    Reconciled = 2,
    Failed = 3,
    Uncertain = 4,
}

public sealed record OperationIntent
{
    public OperationIntent(
        OperationIntentId id,
        OperationId operationId,
        long sequence,
        OperationIntentKind kind,
        string idempotencyKey,
        OperationIntentStatus status,
        DateTimeOffset recordedAtUtc,
        DateTimeOffset? appliedAtUtc = null,
        string? remotePath = null)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation intent identifier cannot be empty.",
                nameof(id));
        }

        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation identifier cannot be empty.",
                nameof(operationId));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        ArgumentException.ThrowIfNullOrWhiteSpace(idempotencyKey);
        if (idempotencyKey.Length > 200 ||
            !string.Equals(idempotencyKey, idempotencyKey.Trim(), StringComparison.Ordinal) ||
            idempotencyKey.Any(char.IsControl))
        {
            throw new ArgumentException(
                "An operation intent idempotency key is invalid.",
                nameof(idempotencyKey));
        }

        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        if (remotePath is not null)
        {
            if (kind != OperationIntentKind.ChallengeWrite ||
                remotePath.Length is < 2 or > 1_024 ||
                remotePath[0] != '/' ||
                remotePath[^1] == '/' ||
                remotePath.Any(char.IsControl))
            {
                throw new ArgumentException(
                    "Only a challenge-write intent can carry a bounded absolute remote path.",
                    nameof(remotePath));
            }
        }

        Id = id;
        OperationId = operationId;
        Sequence = sequence;
        Kind = kind;
        IdempotencyKey = idempotencyKey;
        Status = status;
        RecordedAtUtc = recordedAtUtc.ToUniversalTime();
        AppliedAtUtc = appliedAtUtc?.ToUniversalTime();
        RemotePath = remotePath;
        if (AppliedAtUtc < RecordedAtUtc)
        {
            throw new ArgumentException(
                "The applied timestamp cannot precede the recorded timestamp.",
                nameof(appliedAtUtc));
        }

        if (status is OperationIntentStatus.Applied or OperationIntentStatus.Reconciled &&
            !AppliedAtUtc.HasValue)
        {
            throw new ArgumentException(
                "An applied or reconciled intent requires an applied timestamp.",
                nameof(appliedAtUtc));
        }
    }

    public OperationIntentId Id { get; }

    public OperationId OperationId { get; }

    public long Sequence { get; }

    public OperationIntentKind Kind { get; }

    public string IdempotencyKey { get; }

    public OperationIntentStatus Status { get; }

    public DateTimeOffset RecordedAtUtc { get; }

    public DateTimeOffset? AppliedAtUtc { get; }

    /// <summary>
    /// Gets the exact remote HTTP-01 artifact path. Older migrated
    /// challenge-write intents can be pathless and therefore require manual
    /// cleanup rather than optimistic terminalization.
    /// </summary>
    public string? RemotePath { get; }
}
