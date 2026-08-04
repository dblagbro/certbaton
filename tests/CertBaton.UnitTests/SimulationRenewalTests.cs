using System.Collections;
using CertBaton.Application.Simulation;
using CertBaton.Domain.Renewals;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class SimulationRenewalTests
{
    private static readonly DateTimeOffset simulationStart =
        new(2026, 7, 29, 12, 0, 0, TimeSpan.Zero);

    public static IEnumerable<object[]> FailureStages =>
        RenewalPipeline.Stages.Select(
            static stage => new object[] { stage });

    [TestMethod]
    public void StageDelayMustRemainWithinTheDeveloperSimulationBound()
    {
        _ = new SimulatedRenewalRunner(
            TimeProvider.System,
            TimeSpan.FromMinutes(1));

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () =>
                new SimulatedRenewalRunner(
                    TimeProvider.System,
                    TimeSpan.FromTicks(-1)));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () =>
                new SimulatedRenewalRunner(
                    TimeProvider.System,
                    TimeSpan.FromMinutes(1).Add(TimeSpan.FromTicks(1))));
    }

    [TestMethod]
    public async Task SuccessfulRunRecordsEveryStageInOrder()
    {
        var runner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart));

        var result = await runner.RunAsync(
            Guid.Parse("7f146564-58ed-4a7c-b04f-e3b327fab171"));

        Assert.AreEqual(RenewalTerminalOutcome.Succeeded, result.Outcome);
        Assert.AreEqual(RenewalStage.Cleanup, result.TerminalStage);
        Assert.IsTrue(result.IsSuccess);
        CollectionAssert.AreEqual(
            RenewalPipeline.Stages.ToArray(),
            result.Evidence.Select(static item => item.Stage).ToArray());
        Assert.IsTrue(
            result.Evidence.All(
                static item => item.Outcome == RenewalStageOutcome.Succeeded));
        CollectionAssert.AreEqual(
            Enumerable.Range(1, RenewalPipeline.Stages.Count)
                .Select(static value => (long)value)
                .ToArray(),
            result.Evidence.Select(static item => item.Sequence).ToArray());

        for (var index = 0; index < result.Evidence.Count; index++)
        {
            Assert.AreEqual(
                simulationStart.AddMinutes(index),
                result.Evidence[index].RecordedAtUtc);
        }

        Assert.AreEqual(
            result.Evidence[^1].RecordedAtUtc,
            result.CompletedAtUtc);
    }

    [TestMethod]
    public async Task SameInputsAndTimeProduceEquivalentEvidence()
    {
        var runId = Guid.Parse("9a70c356-206b-41e2-afb7-386b70b8678f");
        var firstRunner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart));
        var secondRunner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart));

        var first = await firstRunner.RunAsync(runId);
        var second = await secondRunner.RunAsync(runId);

        Assert.AreEqual(first.RunId, second.RunId);
        Assert.AreEqual(first.Outcome, second.Outcome);
        Assert.AreEqual(first.TerminalStage, second.TerminalStage);
        Assert.AreEqual(first.CompletedAtUtc, second.CompletedAtUtc);
        CollectionAssert.AreEqual(
            first.Evidence.ToArray(),
            second.Evidence.ToArray());
    }

    [TestMethod]
    [DynamicData(nameof(FailureStages))]
    public async Task InjectedFailureStopsAtConfiguredStage(
        RenewalStage failureStage)
    {
        var runner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart));
        var plan = new RenewalSimulationPlan(
            new SimulationFailure(
                failureStage,
                "simulation.test_failure",
                "A deterministic test failure was injected."));

        var result = await runner.RunAsync(
            Guid.Parse("71b3cfb5-57ab-47bf-8a19-1b82cb15b488"),
            plan);

        var failureIndex = Array.IndexOf(
            RenewalPipeline.Stages.ToArray(),
            failureStage);
        Assert.AreEqual(RenewalTerminalOutcome.Failed, result.Outcome);
        Assert.AreEqual(failureStage, result.TerminalStage);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(failureIndex + 1, result.Evidence.Count);
        Assert.IsTrue(
            result.Evidence
                .Take(failureIndex)
                .All(static item => item.Outcome == RenewalStageOutcome.Succeeded));
        Assert.AreEqual(
            RenewalStageOutcome.Failed,
            result.Evidence[^1].Outcome);
        Assert.AreEqual(
            "simulation.test_failure",
            result.Evidence[^1].Code);
    }

    [TestMethod]
    public async Task VerificationFailureCannotBeReportedAsSuccess()
    {
        var runner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart));
        var plan = new RenewalSimulationPlan(
            new SimulationFailure(RenewalStage.Verification));

        var result = await runner.RunAsync(
            Guid.Parse("2fd3689a-6858-49ce-b4d5-476b62804bb4"),
            plan);

        Assert.AreEqual(RenewalTerminalOutcome.Failed, result.Outcome);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(
            RenewalStageOutcome.Succeeded,
            result.Evidence.Single(
                static item => item.Stage == RenewalStage.Activation).Outcome);
        Assert.AreEqual(
            RenewalStageOutcome.Failed,
            result.Evidence.Single(
                static item => item.Stage == RenewalStage.Verification).Outcome);
        Assert.IsFalse(
            result.Evidence.Any(
                static item => item.Stage == RenewalStage.Cleanup));
    }

    [TestMethod]
    public void ResultCannotBeCreatedBeforeCleanupSucceeds()
    {
        var run = new RenewalRun(
            Guid.Parse("874342c8-85f0-40f0-9205-ed7b7c3642f7"));

        foreach (var stage in RenewalPipeline.Stages.Take(
                     RenewalPipeline.Stages.Count - 1))
        {
            run.RecordStageSucceeded(stage, simulationStart);
        }

        Assert.IsFalse(run.IsTerminal);
        Assert.AreEqual(RenewalStage.Cleanup, run.NextStage);
        Assert.ThrowsExactly<InvalidOperationException>(run.ToResult);
    }

    [TestMethod]
    public async Task ConfiguredCancellationStopsBeforeSafeStageBoundary()
    {
        var runner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart));
        var plan = new RenewalSimulationPlan(
            cancelBeforeStage: RenewalStage.Deployment);

        var result = await runner.RunAsync(
            Guid.Parse("e5be79e4-6850-44b0-9870-0aff176cc687"),
            plan);

        Assert.AreEqual(RenewalTerminalOutcome.Cancelled, result.Outcome);
        Assert.AreEqual(RenewalStage.Deployment, result.TerminalStage);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(
            RenewalStageOutcome.Cancelled,
            result.Evidence[^1].Outcome);
        Assert.AreEqual(RenewalStage.Deployment, result.Evidence[^1].Stage);
        Assert.IsFalse(
            result.Evidence.Any(
                static item => item.Stage == RenewalStage.Activation));
    }

    [TestMethod]
    public async Task CancellationRequestedByObserverStopsAtNextSafeBoundary()
    {
        using var cancellation = new CancellationTokenSource();
        var observed = new List<RenewalEvidenceRecord>();
        var runner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart));

        var result = await runner.RunAsync(
            Guid.Parse("58062efd-2c73-4a9b-8b63-bf2b2ebc10b2"),
            cancellationToken: cancellation.Token,
            evidenceObserver: evidence =>
            {
                observed.Add(evidence);
                if (evidence.Stage == RenewalStage.Issuance)
                {
                    cancellation.Cancel();
                }

                return ValueTask.CompletedTask;
            });

        Assert.AreEqual(RenewalTerminalOutcome.Cancelled, result.Outcome);
        Assert.AreEqual(RenewalStage.Deployment, result.TerminalStage);
        Assert.AreEqual(
            RenewalStageOutcome.Succeeded,
            observed.Single(
                static item => item.Stage == RenewalStage.Issuance).Outcome);
        Assert.AreEqual(
            RenewalStageOutcome.Cancelled,
            observed.Single(
                static item => item.Stage == RenewalStage.Deployment).Outcome);
        CollectionAssert.AreEqual(
            result.Evidence.ToArray(),
            observed.ToArray());
    }

    [TestMethod]
    public async Task PreCancelledTokenStopsBeforePreflight()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var runner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart),
            TimeSpan.FromMinutes(1));

        var result = await runner.RunAsync(
            Guid.Parse("41aca225-ce76-493b-ac23-38e4546996e1"),
            cancellationToken: cancellation.Token);

        Assert.AreEqual(RenewalTerminalOutcome.Cancelled, result.Outcome);
        Assert.AreEqual(RenewalStage.Preflight, result.TerminalStage);
        Assert.HasCount(1, result.Evidence);
        Assert.AreEqual(
            RenewalStageOutcome.Cancelled,
            result.Evidence[0].Outcome);
    }

    [TestMethod]
    public async Task StageDelayUsesInjectedTimeProvider()
    {
        var timeProvider = new ManualDelayTimeProvider(simulationStart);
        var stageDelay = TimeSpan.FromSeconds(30);
        var runner = new SimulatedRenewalRunner(
            timeProvider,
            stageDelay);

        var runTask = runner.RunAsync(
            Guid.Parse("019c0ad8-e632-73e8-b7b5-ebc9bbfb52c8"));

        foreach (var _ in RenewalPipeline.Stages)
        {
            var timer = await timeProvider.GetNextTimerAsync();
            Assert.AreEqual(stageDelay, timer.DueTime);
            Assert.AreEqual(Timeout.InfiniteTimeSpan, timer.Period);
            Assert.IsFalse(runTask.IsCompleted);
            timer.Fire();
        }

        var result = await runTask;

        Assert.AreEqual(RenewalTerminalOutcome.Succeeded, result.Outcome);
        Assert.AreEqual(
            RenewalPipeline.Stages.Count,
            timeProvider.TimerCount);
    }

    [TestMethod]
    public async Task CancellationInterruptsInjectedStageDelayAtSafeBoundary()
    {
        var timeProvider = new ManualDelayTimeProvider(simulationStart);
        using var cancellation = new CancellationTokenSource();
        var runner = new SimulatedRenewalRunner(
            timeProvider,
            TimeSpan.FromSeconds(30));

        var runTask = runner.RunAsync(
            Guid.Parse("019c0ad8-e632-7fb5-bdf1-ec7062181f43"),
            cancellationToken: cancellation.Token);
        _ = await timeProvider.GetNextTimerAsync();
        cancellation.Cancel();

        var result = await runTask;

        Assert.AreEqual(RenewalTerminalOutcome.Cancelled, result.Outcome);
        Assert.AreEqual(RenewalStage.Preflight, result.TerminalStage);
        Assert.HasCount(1, result.Evidence);
        Assert.AreEqual(
            RenewalStageOutcome.Cancelled,
            result.Evidence[0].Outcome);
    }

    [TestMethod]
    public async Task EvidenceObserverIsAwaitedBeforeTheNextStage()
    {
        var observerEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseObserver = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var observed = new List<RenewalEvidenceRecord>();
        var runner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart));

        var runTask = runner.RunAsync(
            Guid.Parse("354bebc0-006e-4882-aec6-0635b18b62bf"),
            evidenceObserver: async evidence =>
            {
                observed.Add(evidence);
                if (evidence.Stage == RenewalStage.Preflight)
                {
                    observerEntered.SetResult();
                    await releaseObserver.Task;
                }
            });

        await observerEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.IsFalse(runTask.IsCompleted);
        Assert.HasCount(1, observed);

        releaseObserver.SetResult();
        var result = await runTask;

        Assert.AreEqual(RenewalTerminalOutcome.Succeeded, result.Outcome);
        CollectionAssert.AreEqual(
            result.Evidence.ToArray(),
            observed.ToArray());
    }

    [TestMethod]
    public async Task CompletedEvidenceSnapshotIsReadOnly()
    {
        var runner = new SimulatedRenewalRunner(
            new IncrementingTimeProvider(simulationStart));
        var result = await runner.RunAsync(
            Guid.Parse("89fdb68f-901f-43c0-bcd3-dc422567c6d1"));
        var evidence = (IList)result.Evidence;

        Assert.IsTrue(evidence.IsReadOnly);
        Assert.ThrowsExactly<NotSupportedException>(evidence.Clear);
    }

    private class IncrementingTimeProvider : TimeProvider
    {
        private DateTimeOffset nextTimestamp;

        public IncrementingTimeProvider(DateTimeOffset start)
        {
            nextTimestamp = start;
        }

        public override DateTimeOffset GetUtcNow()
        {
            var current = nextTimestamp;
            nextTimestamp = nextTimestamp.AddMinutes(1);
            return current;
        }
    }

    private sealed class ManualDelayTimeProvider : IncrementingTimeProvider
    {
        private readonly global::System.Threading.Channels.Channel<ManualTimer> timers =
            global::System.Threading.Channels.Channel.CreateUnbounded<ManualTimer>();
        private int timerCount;

        public ManualDelayTimeProvider(DateTimeOffset start)
            : base(start)
        {
        }

        public int TimerCount => Volatile.Read(ref timerCount);

        public override ITimer CreateTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            var timer = new ManualTimer(
                callback,
                state,
                dueTime,
                period);
            Interlocked.Increment(ref timerCount);
            if (!timers.Writer.TryWrite(timer))
            {
                throw new InvalidOperationException(
                    "The manual timer queue was unexpectedly closed.");
            }

            return timer;
        }

        public async Task<ManualTimer> GetNextTimerAsync() =>
            await timers.Reader.ReadAsync().AsTask().WaitAsync(
                TimeSpan.FromSeconds(5));
    }

    private sealed class ManualTimer : ITimer
    {
        private readonly TimerCallback callback;
        private readonly object? state;
        private int fired;
        private int disposed;

        public ManualTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            this.callback = callback;
            this.state = state;
            DueTime = dueTime;
            Period = period;
        }

        public TimeSpan DueTime { get; private set; }

        public TimeSpan Period { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            if (Volatile.Read(ref disposed) != 0)
            {
                return false;
            }

            DueTime = dueTime;
            Period = period;
            return true;
        }

        public void Fire()
        {
            if (Interlocked.Exchange(ref fired, 1) == 0 &&
                Volatile.Read(ref disposed) == 0)
            {
                callback(state);
            }
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref disposed, 1);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
