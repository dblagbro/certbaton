namespace CertBaton.Domain.Renewals;

public sealed record RenewalEvidenceRecord
{
    internal RenewalEvidenceRecord(
        long sequence,
        RenewalStage stage,
        RenewalStageOutcome outcome,
        DateTimeOffset recordedAtUtc,
        string code,
        string description)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);

        Sequence = sequence;
        Stage = stage;
        Outcome = outcome;
        RecordedAtUtc = recordedAtUtc.ToUniversalTime();
        Code = code;
        Description = description;
    }

    public long Sequence { get; }

    public RenewalStage Stage { get; }

    public RenewalStageOutcome Outcome { get; }

    public DateTimeOffset RecordedAtUtc { get; }

    public string Code { get; }

    public string Description { get; }
}
