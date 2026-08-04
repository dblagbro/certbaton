using CertBaton.Domain.Renewals;

namespace CertBaton.Application.Simulation;

public sealed class SimulatedRenewalRunner
{
    private static readonly Func<RenewalEvidenceRecord, ValueTask> noOpEvidenceObserver =
        static _ => ValueTask.CompletedTask;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan stageDelay;

    public SimulatedRenewalRunner(
        TimeProvider timeProvider,
        TimeSpan stageDelay = default)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (stageDelay < TimeSpan.Zero ||
            stageDelay > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(stageDelay),
                stageDelay,
                "The simulated stage delay must be between zero and one minute.");
        }

        this.timeProvider = timeProvider;
        this.stageDelay = stageDelay;
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
            if (stageDelay > TimeSpan.Zero &&
                !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(
                            stageDelay,
                            timeProvider,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (
                    cancellationToken.IsCancellationRequested)
                {
                    // Cancellation is recorded as evidence at the safe stage
                    // boundary immediately below.
                }
            }

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
