using CertBaton.Domain.Renewals;

namespace CertBaton.Application.Simulation;

public sealed class SimulatedRenewalRunner
{
    private static readonly Func<RenewalEvidenceRecord, ValueTask> noOpEvidenceObserver =
        static _ => ValueTask.CompletedTask;
    private readonly TimeProvider timeProvider;

    public SimulatedRenewalRunner(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        this.timeProvider = timeProvider;
    }

    public async Task<RenewalRunResult> RunAsync(
        Guid runId,
        RenewalSimulationPlan? plan = null,
        Func<RenewalEvidenceRecord, ValueTask>? evidenceObserver = null,
        CancellationToken cancellationToken = default)
    {
        plan ??= new RenewalSimulationPlan();
        evidenceObserver ??= noOpEvidenceObserver;
        var run = new RenewalRun(runId);

        while (run.NextStage is { } stage)
        {
            if (cancellationToken.IsCancellationRequested ||
                plan.CancelBeforeStage == stage)
            {
                run.RecordCancellation(stage, GetUtcNow());
                await ObserveLatestEvidenceAsync(run, evidenceObserver).ConfigureAwait(false);
                break;
            }

            if (plan.Failure?.Stage == stage)
            {
                run.RecordStageFailed(
                    stage,
                    GetUtcNow(),
                    plan.Failure.Code,
                    plan.Failure.Description);
                await ObserveLatestEvidenceAsync(run, evidenceObserver).ConfigureAwait(false);
                break;
            }

            run.RecordStageSucceeded(stage, GetUtcNow());
            await ObserveLatestEvidenceAsync(run, evidenceObserver).ConfigureAwait(false);
        }

        return run.ToResult();
    }

    private DateTimeOffset GetUtcNow() =>
        timeProvider.GetUtcNow().ToUniversalTime();

    private static ValueTask ObserveLatestEvidenceAsync(
        RenewalRun run,
        Func<RenewalEvidenceRecord, ValueTask> evidenceObserver) =>
        evidenceObserver(run.Evidence[^1]);
}
