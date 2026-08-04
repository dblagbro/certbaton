using System.Collections.ObjectModel;

namespace CertBaton.Domain.Renewals;

public sealed class RenewalRun
{
    private const string StageSucceededCode = "simulation.stage_succeeded";
    private readonly List<RenewalEvidenceRecord> evidence = [];
    private readonly ReadOnlyCollection<RenewalEvidenceRecord> evidenceView;
    private int nextStageIndex;

    public RenewalRun(Guid runId)
    {
        if (runId == Guid.Empty)
        {
            throw new ArgumentException("A renewal run identifier cannot be empty.", nameof(runId));
        }

        RunId = runId;
        evidenceView = evidence.AsReadOnly();
    }

    public Guid RunId { get; }

    public RenewalTerminalOutcome? Outcome { get; private set; }

    public RenewalStage? TerminalStage { get; private set; }

    public DateTimeOffset? CompletedAtUtc { get; private set; }

    public bool IsTerminal => Outcome.HasValue;

    public RenewalStage? NextStage =>
        IsTerminal || nextStageIndex >= RenewalPipeline.Stages.Count
            ? null
            : RenewalPipeline.Stages[nextStageIndex];

    public IReadOnlyList<RenewalEvidenceRecord> Evidence => evidenceView;

    public void RecordStageSucceeded(
        RenewalStage stage,
        DateTimeOffset recordedAtUtc)
    {
        EnsureExpectedStage(stage);

        AppendEvidence(
            stage,
            RenewalStageOutcome.Succeeded,
            recordedAtUtc,
            StageSucceededCode,
            $"The simulated {stage} stage completed.");
        nextStageIndex++;

        if (nextStageIndex == RenewalPipeline.Stages.Count)
        {
            SetTerminal(
                RenewalTerminalOutcome.Succeeded,
                stage,
                recordedAtUtc);
        }
    }

    public void RecordStageFailed(
        RenewalStage stage,
        DateTimeOffset recordedAtUtc,
        string code,
        string description)
    {
        EnsureExpectedStage(stage);

        AppendEvidence(
            stage,
            RenewalStageOutcome.Failed,
            recordedAtUtc,
            code,
            description);
        SetTerminal(
            RenewalTerminalOutcome.Failed,
            stage,
            recordedAtUtc);
    }

    public void RecordCancellation(
        RenewalStage stage,
        DateTimeOffset recordedAtUtc)
    {
        EnsureExpectedStage(stage);

        AppendEvidence(
            stage,
            RenewalStageOutcome.Cancelled,
            recordedAtUtc,
            "simulation.cancelled",
            $"The simulated run was cancelled before entering the {stage} stage.");
        SetTerminal(
            RenewalTerminalOutcome.Cancelled,
            stage,
            recordedAtUtc);
    }

    public RenewalRunResult ToResult()
    {
        if (!Outcome.HasValue ||
            !TerminalStage.HasValue ||
            !CompletedAtUtc.HasValue)
        {
            throw new InvalidOperationException(
                "A renewal result cannot be created before the run reaches a terminal outcome.");
        }

        return new RenewalRunResult(
            RunId,
            Outcome.Value,
            TerminalStage.Value,
            CompletedAtUtc.Value,
            Array.AsReadOnly(evidence.ToArray()));
    }

    private void EnsureExpectedStage(RenewalStage stage)
    {
        if (IsTerminal)
        {
            throw new InvalidOperationException(
                "A terminal renewal run cannot accept more evidence.");
        }

        if (NextStage != stage)
        {
            throw new InvalidOperationException(
                $"The next renewal stage is {NextStage}; evidence for {stage} is not valid.");
        }
    }

    private void AppendEvidence(
        RenewalStage stage,
        RenewalStageOutcome outcome,
        DateTimeOffset recordedAtUtc,
        string code,
        string description)
    {
        evidence.Add(
            new RenewalEvidenceRecord(
                evidence.Count + 1,
                stage,
                outcome,
                recordedAtUtc,
                code,
                description));
    }

    private void SetTerminal(
        RenewalTerminalOutcome outcome,
        RenewalStage stage,
        DateTimeOffset completedAtUtc)
    {
        Outcome = outcome;
        TerminalStage = stage;
        CompletedAtUtc = completedAtUtc.ToUniversalTime();
    }
}
