using System.Globalization;
using CertBaton.Domain.Targets;

namespace CertBaton.Domain.Operations;

public readonly record struct AuditEventId
{
    public AuditEventId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "An audit-event identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static AuditEventId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public sealed record AuditEvent
{
    public AuditEvent(
        AuditEventId id,
        long sequence,
        OperationId? operationId,
        TargetId? targetId,
        string actorSid,
        string eventType,
        DateTimeOffset occurredAtUtc,
        string code,
        string description)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An audit-event identifier cannot be empty.",
                nameof(id));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        if (operationId?.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation identifier cannot be empty.",
                nameof(operationId));
        }

        if (targetId?.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A target identifier cannot be empty.",
                nameof(targetId));
        }

        Id = id;
        Sequence = sequence;
        OperationId = operationId;
        TargetId = targetId;
        ActorSid = ValidateText(actorSid, 184, nameof(actorSid), minimumLength: 5);
        EventType = ValidateText(eventType, 100, nameof(eventType));
        OccurredAtUtc = occurredAtUtc.ToUniversalTime();
        Code = ValidateText(code, 128, nameof(code));
        Description = ValidateText(description, 1_024, nameof(description));
    }

    public AuditEventId Id { get; }

    public long Sequence { get; }

    public OperationId? OperationId { get; }

    public TargetId? TargetId { get; }

    public string ActorSid { get; }

    public string EventType { get; }

    public DateTimeOffset OccurredAtUtc { get; }

    public string Code { get; }

    public string Description { get; }

    private static string ValidateText(
        string value,
        int maximumLength,
        string parameterName,
        int minimumLength = 1)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length < minimumLength ||
            value.Length > maximumLength ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException(
                "The audit-event value is invalid.",
                parameterName);
        }

        return value;
    }
}
