using System.IO.Pipes;
using System.Security.Principal;
using CertBaton.Application.Simulation;
using CertBaton.Application.Simulation.Persistence;
using CertBaton.Contracts;
using CertBaton.Domain.Renewals;
using CertBaton.Ipc.NamedPipes;
using CertBaton.Persistence.Sqlite;
using CertBaton.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class SimulationServiceTests
{
    private readonly List<string> testDirectories = [];

    [TestCleanup]
    public void Cleanup()
    {
        foreach (var directory in testDirectories)
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [TestMethod]
    public void StartPolicySeparatesDevelopmentAndInstalledServiceCallers()
    {
        var ordinaryIdentity = CreateIdentity(isAdministrator: false);
        var administratorIdentity = CreateIdentity(isAdministrator: true);
        var developmentPolicy = new SimulationAccessPolicy(
            new IpcServerOptions
            {
                SecurityProfile =
                    PipeServerSecurityProfile.CurrentUserDevelopment,
            });
        var installedPolicy = new SimulationAccessPolicy(
            new IpcServerOptions
            {
                SecurityProfile = PipeServerSecurityProfile.InstalledService,
            });

        Assert.IsTrue(developmentPolicy.CanStart(ordinaryIdentity));
        Assert.IsFalse(installedPolicy.CanStart(ordinaryIdentity));
        Assert.IsTrue(installedPolicy.CanStart(administratorIdentity));
    }

    [TestMethod]
    public async Task InstalledServiceDeniesOrdinaryStartBeforeEnqueue()
    {
        var options = new IpcServerOptions
        {
            PipeName = $"CertBaton.UnitTests.{Guid.NewGuid():N}",
            SecurityProfile = PipeServerSecurityProfile.InstalledService,
        };
        var coordinator = new StubSimulationCoordinator(CreateQueuedDetails());
        var timeProvider = new IncrementingTimeProvider(runClockStart);
        var worker = new IpcWorker(
            new CertBatonPipeServer(options, timeProvider: timeProvider),
            coordinator,
            new SimulationAccessPolicy(options),
            NullLogger<IpcWorker>.Instance,
            timeProvider);
        var request = IpcRequest.CreateSimulationStart(
            timeProvider,
            Guid.Parse("2d026820-0284-4f19-b30c-5403170c38c6"));

        var response = await worker.HandleRequestAsync(
            request,
            CreateIdentity(isAdministrator: false),
            CancellationToken.None);

        Assert.IsFalse(response.Success);
        Assert.AreEqual(
            "simulation_start_forbidden",
            response.Error?.Code);
        Assert.AreEqual(0, coordinator.StartCallCount);
    }

    [TestMethod]
    public async Task DevelopmentStartDispatchesTypedFailurePlan()
    {
        var options = new IpcServerOptions
        {
            PipeName = $"CertBaton.UnitTests.{Guid.NewGuid():N}",
            SecurityProfile =
                PipeServerSecurityProfile.CurrentUserDevelopment,
        };
        var queued = CreateQueuedDetails(RenewalStage.Verification);
        var coordinator = new StubSimulationCoordinator(queued);
        var timeProvider = new IncrementingTimeProvider(runClockStart);
        var worker = new IpcWorker(
            new CertBatonPipeServer(options, timeProvider: timeProvider),
            coordinator,
            new SimulationAccessPolicy(options),
            NullLogger<IpcWorker>.Instance,
            timeProvider);
        var idempotencyKey =
            Guid.Parse("a4906644-2312-49d2-a874-14f16add45f3");
        var request = IpcRequest.CreateSimulationStart(
            timeProvider,
            idempotencyKey,
            SimulationContractValues.VerificationStage);

        var response = await worker.HandleRequestAsync(
            request,
            CreateIdentity(isAdministrator: false),
            CancellationToken.None);

        Assert.IsTrue(response.Success);
        Assert.AreEqual(1, coordinator.StartCallCount);
        Assert.AreEqual(idempotencyKey, coordinator.ObservedIdempotencyKey);
        Assert.AreEqual(
            RenewalStage.Verification,
            coordinator.ObservedFailureStage);
        Assert.AreEqual(
            SimulationContractValues.QueuedStatus,
            response.Result?.SimulationRun?.Status);
    }

    [TestMethod]
    public async Task IdempotencyPlanConflictReturnsStableSanitizedError()
    {
        var options = new IpcServerOptions
        {
            PipeName = $"CertBaton.UnitTests.{Guid.NewGuid():N}",
            SecurityProfile =
                PipeServerSecurityProfile.CurrentUserDevelopment,
        };
        var timeProvider = new IncrementingTimeProvider(runClockStart);
        var worker = new IpcWorker(
            new CertBatonPipeServer(options, timeProvider: timeProvider),
            new ThrowingSimulationCoordinator(
                new SimulationIdempotencyConflictException()),
            new SimulationAccessPolicy(options),
            NullLogger<IpcWorker>.Instance,
            timeProvider);
        var request = IpcRequest.CreateSimulationStart(
            timeProvider,
            Guid.Parse("cc010739-6855-46d7-99b4-b2827c780e70"),
            SimulationContractValues.CleanupStage);

        var response = await worker.HandleRequestAsync(
            request,
            CreateIdentity(isAdministrator: false),
            CancellationToken.None);

        Assert.IsFalse(response.Success);
        Assert.AreEqual(
            "simulation_idempotency_conflict",
            response.Error?.Code);
        Assert.AreEqual(
            "The idempotency key is already associated with a different simulation plan.",
            response.Error?.Message);
    }

    [TestMethod]
    public async Task CoordinatorCompletesPersistedRunAndPublishesValidContract()
    {
        var coordinator = CreateCoordinator(out var store);
        await coordinator.StartAsync(CancellationToken.None);

        try
        {
            var accepted = await coordinator.StartAsync(
                Guid.Parse("8b788c4d-b7c0-4f99-87bd-d6ee2efc635d"),
                failureStage: null,
                CancellationToken.None);
            Assert.AreEqual(SimulationJobStatus.Queued, accepted.Job.Status);

            var completed = await WaitForTerminalAsync(coordinator);
            Assert.AreEqual(
                SimulationJobStatus.Succeeded,
                completed.Job.Status);
            Assert.HasCount(9, completed.Evidence);
            Assert.AreEqual(
                SimulationEvidenceKind.Terminal,
                completed.Evidence[^1].Kind);
            Assert.IsTrue(
                completed.Evidence
                    .Take(RenewalPipeline.Stages.Count)
                    .All(
                        static item =>
                            item.Kind == SimulationEvidenceKind.Stage &&
                            item.Outcome == RenewalStageOutcome.Succeeded));

            var contract = SimulationContractMapper.ToContract(completed);
            Assert.IsTrue(
                contract.TryValidate(out var contractError),
                contractError);
            Assert.AreEqual(
                SimulationContractValues.SucceededStatus,
                contract.Status);
            Assert.AreEqual(
                SimulationContractValues.CleanupStage,
                contract.TerminalStage);

            var persisted = store.FindJobWithEvidence(completed.Job.JobId);
            Assert.IsNotNull(persisted);
            Assert.AreEqual(
                SimulationJobStatus.Succeeded,
                persisted.Job.Status);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
            coordinator.Dispose();
        }
    }

    [TestMethod]
    public async Task InjectedFailureIsPersistedAndCannotMapToSuccess()
    {
        var coordinator = CreateCoordinator(out _);
        await coordinator.StartAsync(CancellationToken.None);

        try
        {
            _ = await coordinator.StartAsync(
                Guid.Parse("b9b61494-34f9-4909-8971-3c1a6205e938"),
                RenewalStage.Verification,
                CancellationToken.None);

            var completed = await WaitForTerminalAsync(coordinator);
            Assert.AreEqual(SimulationJobStatus.Failed, completed.Job.Status);
            Assert.IsFalse(
                completed.Evidence.Any(
                    static item =>
                        item.Stage == RenewalStage.Cleanup));

            var contract = SimulationContractMapper.ToContract(completed);
            Assert.AreEqual(
                SimulationContractValues.FailedStatus,
                contract.Status);
            Assert.AreEqual(
                SimulationContractValues.VerificationStage,
                contract.TerminalStage);
            Assert.AreNotEqual(
                SimulationContractValues.SucceededOutcome,
                contract.Outcome);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
            coordinator.Dispose();
        }
    }

    [TestMethod]
    public async Task ActiveSameKeyAndPlanRetryReturnsExistingDurableJob()
    {
        var coordinator = CreateCoordinator(out _);
        var idempotencyKey =
            Guid.Parse("9e97fc46-e251-4f3c-9a99-4428d9905fb1");
        var firstTask = coordinator.StartAsync(
            idempotencyKey,
            RenewalStage.Deployment,
            CancellationToken.None);
        var retryTask = coordinator.StartAsync(
            idempotencyKey,
            RenewalStage.Deployment,
            CancellationToken.None);
        var differentRequestTask = coordinator.StartAsync(
            Guid.Parse("efc1f460-52e4-4e71-b587-385814b19166"),
            RenewalStage.Deployment,
            CancellationToken.None);
        await coordinator.StartAsync(CancellationToken.None);

        try
        {
            var first = await firstTask;
            var retry = await retryTask;

            Assert.AreEqual(SimulationJobStatus.Queued, first.Job.Status);
            Assert.AreEqual(first.Job.JobId, retry.Job.JobId);
            Assert.AreEqual(first.Job.RequestKey, retry.Job.RequestKey);
            await Assert.ThrowsExactlyAsync<SimulationAlreadyActiveException>(
                async () => await differentRequestTask);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
            coordinator.Dispose();
        }
    }

    [TestMethod]
    public async Task CancellationBeforeCoordinatorClaimCreatesNoDurableJob()
    {
        var coordinator = CreateCoordinator(out var store);
        using var cancellation = new CancellationTokenSource();
        var startTask = coordinator.StartAsync(
            Guid.Parse("b79fdb6d-93f8-44d7-b673-e6522b81464b"),
            failureStage: null,
            cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await startTask);
        await coordinator.StartAsync(CancellationToken.None);
        await coordinator.StopAsync(CancellationToken.None);
        store.Initialize(runClockStart);

        Assert.IsNull(coordinator.Latest);
        Assert.IsNull(store.GetLatestJobWithEvidence());
        coordinator.Dispose();
    }

    [TestMethod]
    [DoNotParallelize]
    public async Task CoordinatorClaimBeforeCancellationFinishesDurableCreation()
    {
        var directory = CreateTestDirectory();
        var innerStore = new SqliteSimulationJobStore(
            Path.Combine(directory, "state.db"));
        var blockingStore = new BlockingCreateSimulationJobStore(innerStore);
        var timeProvider = new IncrementingTimeProvider(runClockStart);
        var coordinator = new SimulationCoordinator(
            blockingStore,
            new SimulatedRenewalRunner(timeProvider),
            timeProvider,
            NullLogger<SimulationCoordinator>.Instance);
        await coordinator.StartAsync(CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        var startTask = coordinator.StartAsync(
            Guid.Parse("2d0f99cf-bde0-4794-8156-ef2e9ef8cbbe"),
            failureStage: null,
            cancellation.Token);

        try
        {
            await blockingStore.CreateEntered.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
            blockingStore.ReleaseCreate();

            var accepted = await startTask;

            Assert.AreEqual(SimulationJobStatus.Queued, accepted.Job.Status);
            Assert.IsNotNull(innerStore.FindJob(accepted.Job.JobId));
        }
        finally
        {
            blockingStore.ReleaseCreate();
            await coordinator.StopAsync(CancellationToken.None);
            coordinator.Dispose();
        }
    }

    [TestMethod]
    public async Task TerminalIdempotencyReplayDoesNotReplaceGlobalLatest()
    {
        var coordinator = CreateCoordinator(out _);
        await coordinator.StartAsync(CancellationToken.None);

        try
        {
            var firstKey =
                Guid.Parse("df825474-36f8-4e7f-b1da-2e59f7d248ee");
            _ = await coordinator.StartAsync(
                firstKey,
                failureStage: null,
                CancellationToken.None);
            var first = await WaitForTerminalAsync(coordinator);
            Assert.AreEqual(SimulationJobStatus.Succeeded, first.Job.Status);

            _ = await coordinator.StartAsync(
                Guid.Parse("05fd4b44-e073-47b5-9da9-a08bf416ccd1"),
                RenewalStage.Verification,
                CancellationToken.None);
            var second = await WaitForTerminalAsync(coordinator);
            Assert.AreEqual(SimulationJobStatus.Failed, second.Job.Status);

            var replay = await coordinator.StartAsync(
                firstKey,
                failureStage: null,
                CancellationToken.None);

            Assert.AreEqual(first.Job.JobId, replay.Job.JobId);
            Assert.AreEqual(SimulationJobStatus.Succeeded, replay.Job.Status);
            Assert.AreEqual(second.Job.JobId, coordinator.Latest?.Job.JobId);
            Assert.AreEqual(
                SimulationJobStatus.Failed,
                coordinator.Latest?.Job.Status);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
            coordinator.Dispose();
        }
    }

    [TestMethod]
    public async Task HistoricalReplaySucceedsWhileANewerJobIsQueued()
    {
        var firstCoordinator = CreateCoordinator(out var store);
        var historicalKey =
            Guid.Parse("a937e44d-d25a-4e83-b039-8a52c3afcf43");
        await firstCoordinator.StartAsync(CancellationToken.None);
        SimulationJobDetails historical;
        try
        {
            _ = await firstCoordinator.StartAsync(
                historicalKey,
                failureStage: null,
                CancellationToken.None);
            historical = await WaitForTerminalAsync(firstCoordinator);
        }
        finally
        {
            await firstCoordinator.StopAsync(CancellationToken.None);
            firstCoordinator.Dispose();
        }

        var timeProvider = new IncrementingTimeProvider(
            runClockStart.AddHours(1));
        var coordinator = new SimulationCoordinator(
            store,
            new SimulatedRenewalRunner(timeProvider),
            timeProvider,
            NullLogger<SimulationCoordinator>.Instance);
        var newerTask = coordinator.StartAsync(
            Guid.Parse("d06ded6a-23b6-4194-a0dc-8e19edcefb0e"),
            RenewalStage.Activation,
            CancellationToken.None);
        var replayTask = coordinator.StartAsync(
            historicalKey,
            failureStage: null,
            CancellationToken.None);
        await coordinator.StartAsync(CancellationToken.None);

        try
        {
            var newer = await newerTask;
            var replay = await replayTask;

            Assert.AreEqual(
                SimulationJobStatus.Queued,
                newer.Job.Status);
            Assert.AreEqual(
                historical.Job.JobId,
                replay.Job.JobId);
            Assert.AreEqual(
                SimulationJobStatus.Succeeded,
                replay.Job.Status);
            Assert.AreEqual(
                newer.Job.JobId,
                coordinator.Latest?.Job.JobId);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
            coordinator.Dispose();
        }
    }

    private SimulationCoordinator CreateCoordinator(
        out SqliteSimulationJobStore store)
    {
        var directory = CreateTestDirectory();
        store = new SqliteSimulationJobStore(
            Path.Combine(directory, "state.db"));
        var timeProvider = new IncrementingTimeProvider(
            new DateTimeOffset(2026, 7, 29, 20, 0, 0, TimeSpan.Zero));

        return new SimulationCoordinator(
            store,
            new SimulatedRenewalRunner(timeProvider),
            timeProvider,
            NullLogger<SimulationCoordinator>.Instance);
    }

    private string CreateTestDirectory()
    {
        var directory = Directory
            .CreateTempSubdirectory("CertBaton.ServiceTests-")
            .FullName;
        testDirectories.Add(directory);
        return directory;
    }

    private static async Task<SimulationJobDetails> WaitForTerminalAsync(
        SimulationCoordinator coordinator)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!timeout.IsCancellationRequested)
        {
            var latest = coordinator.Latest;
            if (latest?.Job.Status is
                SimulationJobStatus.Succeeded or
                SimulationJobStatus.Failed or
                SimulationJobStatus.Cancelled or
                SimulationJobStatus.Interrupted)
            {
                return latest;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(10), timeout.Token);
        }

        throw new AssertFailedException(
            "The service-owned simulation did not reach a terminal state.");
    }

    private static PipeClientIdentity CreateIdentity(bool isAdministrator) =>
        new(
            "S-1-5-21-1000",
            isAdministrator,
            TokenImpersonationLevel.Identification);

    private static readonly DateTimeOffset runClockStart =
        new(2026, 7, 29, 19, 0, 0, TimeSpan.Zero);

    private static SimulationJobDetails CreateQueuedDetails(
        RenewalStage? failureStage = null) =>
        new(
            new SimulationJobSnapshot(
                Guid.Parse("0f2eaf3c-450b-4d25-a8ae-45822fa84af3"),
                "unit-test-request",
                failureStage,
                SimulationJobStatus.Queued,
                runClockStart,
                runClockStart,
                null,
                null,
                null),
            Array.Empty<SimulationJobEvidence>());

    private sealed class IncrementingTimeProvider : TimeProvider
    {
        private readonly object gate = new();
        private DateTimeOffset next;

        public IncrementingTimeProvider(DateTimeOffset start)
        {
            next = start;
        }

        public override DateTimeOffset GetUtcNow()
        {
            lock (gate)
            {
                var current = next;
                next = next.AddMilliseconds(1);
                return current;
            }
        }
    }

    private sealed class StubSimulationCoordinator : ISimulationCoordinator
    {
        private readonly SimulationJobDetails startResult;

        public StubSimulationCoordinator(SimulationJobDetails startResult)
        {
            this.startResult = startResult;
        }

        public SimulationJobDetails? Latest => startResult;

        public int StartCallCount { get; private set; }

        public Guid? ObservedIdempotencyKey { get; private set; }

        public RenewalStage? ObservedFailureStage { get; private set; }

        public Task<SimulationJobDetails> StartAsync(
            Guid idempotencyKey,
            RenewalStage? failureStage,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StartCallCount++;
            ObservedIdempotencyKey = idempotencyKey;
            ObservedFailureStage = failureStage;
            return Task.FromResult(startResult);
        }
    }

    private sealed class ThrowingSimulationCoordinator : ISimulationCoordinator
    {
        private readonly Exception exception;

        public ThrowingSimulationCoordinator(Exception exception)
        {
            this.exception = exception;
        }

        public SimulationJobDetails? Latest => null;

        public Task<SimulationJobDetails> StartAsync(
            Guid idempotencyKey,
            RenewalStage? failureStage,
            CancellationToken cancellationToken)
        {
            _ = idempotencyKey;
            _ = failureStage;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromException<SimulationJobDetails>(exception);
        }
    }

    private sealed class BlockingCreateSimulationJobStore : ISimulationJobStore
    {
        private readonly ISimulationJobStore inner;
        private readonly TaskCompletionSource createEntered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource releaseCreate =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public BlockingCreateSimulationJobStore(ISimulationJobStore inner)
        {
            this.inner = inner;
        }

        public Task CreateEntered => createEntered.Task;

        public void Initialize(DateTimeOffset recoveredAtUtc) =>
            inner.Initialize(recoveredAtUtc);

        public SimulationJobSnapshot CreateOrGetJob(
            Guid jobId,
            string requestKey,
            RenewalStage? failureStage,
            DateTimeOffset createdAtUtc)
        {
            createEntered.TrySetResult();
            if (!releaseCreate.Task.Wait(TimeSpan.FromSeconds(5)))
            {
                throw new TimeoutException(
                    "The test did not release durable simulation creation.");
            }

            return inner.CreateOrGetJob(
                jobId,
                requestKey,
                failureStage,
                createdAtUtc);
        }

        public SimulationJobSnapshot? TryClaimNextQueuedJob(
            Guid executionEpoch,
            DateTimeOffset claimedAtUtc) =>
            inner.TryClaimNextQueuedJob(executionEpoch, claimedAtUtc);

        public void AppendStageEvidence(
            Guid jobId,
            Guid executionEpoch,
            RenewalStage stage,
            RenewalStageOutcome outcome,
            DateTimeOffset recordedAtUtc,
            string code,
            string description) =>
            inner.AppendStageEvidence(
                jobId,
                executionEpoch,
                stage,
                outcome,
                recordedAtUtc,
                code,
                description);

        public void CompleteJob(
            Guid jobId,
            Guid executionEpoch,
            SimulationJobStatus terminalStatus,
            DateTimeOffset completedAtUtc,
            string code,
            string description) =>
            inner.CompleteJob(
                jobId,
                executionEpoch,
                terminalStatus,
                completedAtUtc,
                code,
                description);

        public SimulationJobSnapshot? FindJob(Guid jobId) =>
            inner.FindJob(jobId);

        public SimulationJobDetails? FindJobWithEvidence(Guid jobId) =>
            inner.FindJobWithEvidence(jobId);

        public SimulationJobDetails? GetLatestJobWithEvidence() =>
            inner.GetLatestJobWithEvidence();

        public IReadOnlyList<SimulationJobEvidence> ReadEvidence(Guid jobId) =>
            inner.ReadEvidence(jobId);

        public void ReleaseCreate() =>
            releaseCreate.TrySetResult();
    }
}
