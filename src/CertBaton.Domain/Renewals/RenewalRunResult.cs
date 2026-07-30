namespace CertBaton.Domain.Renewals;

public sealed record RenewalRunResult
{
    internal RenewalRunResult(
        Guid runId,
        RenewalTerminalOutcome outcome,
        RenewalStage terminalStage,
        DateTimeOffset completedAtUtc,
        IReadOnlyList<RenewalEvidenceRecord> evidence)
    {
        RunId = runId;
        Outcome = outcome;
        TerminalStage = terminalStage;
        CompletedAtUtc = completedAtUtc.ToUniversalTime();
        Evidence = evidence;
    }

    public Guid RunId { get; }

    public RenewalTerminalOutcome Outcome { get; }

    public RenewalStage TerminalStage { get; }

    public DateTimeOffset CompletedAtUtc { get; }

    public IReadOnlyList<RenewalEvidenceRecord> Evidence { get; }

    public bool IsSuccess => Outcome == RenewalTerminalOutcome.Succeeded;
}
