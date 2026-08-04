using System.Globalization;
using CertBaton.Domain.Targets;

namespace CertBaton.Domain.Scheduling;

public readonly record struct RenewalPolicyId
{
    public RenewalPolicyId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "A renewal policy identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static RenewalPolicyId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public sealed record RenewalPolicy
{
    public RenewalPolicy(
        RenewalPolicyId id,
        TargetId targetId,
        int renewBeforeDays,
        int checkIntervalMinutes,
        bool enabled,
        DateTimeOffset? nextDueAtUtc,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A renewal policy identifier cannot be empty.",
                nameof(id));
        }

        if (targetId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A target identifier cannot be empty.",
                nameof(targetId));
        }

        if (renewBeforeDays is < 1 or > 90)
        {
            throw new ArgumentOutOfRangeException(
                nameof(renewBeforeDays),
                renewBeforeDays,
                "The renewal window must be between 1 and 90 days.");
        }

        if (checkIntervalMinutes is < 15 or > 10_080)
        {
            throw new ArgumentOutOfRangeException(
                nameof(checkIntervalMinutes),
                checkIntervalMinutes,
                "The schedule interval must be between 15 minutes and 7 days.");
        }

        Id = id;
        TargetId = targetId;
        RenewBeforeDays = renewBeforeDays;
        CheckIntervalMinutes = checkIntervalMinutes;
        Enabled = enabled;
        NextDueAtUtc = nextDueAtUtc?.ToUniversalTime();
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        UpdatedAtUtc = updatedAtUtc.ToUniversalTime();
        if (UpdatedAtUtc < CreatedAtUtc)
        {
            throw new ArgumentException(
                "The updated timestamp cannot precede the created timestamp.",
                nameof(updatedAtUtc));
        }
    }

    public RenewalPolicyId Id { get; }

    public TargetId TargetId { get; }

    public int RenewBeforeDays { get; }

    public int CheckIntervalMinutes { get; }

    public bool Enabled { get; }

    public DateTimeOffset? NextDueAtUtc { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; }
}
