using System.Globalization;
using CertBaton.Application.Simulation.Persistence;
using CertBaton.Domain.Renewals;
using CertBaton.Persistence.Sqlite;
using Microsoft.Data.Sqlite;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class SqliteSimulationJobStoreTests
{
    private static readonly DateTimeOffset testStart =
        new(2026, 7, 29, 18, 0, 0, TimeSpan.Zero);
    private static readonly Guid executionEpoch =
        Guid.Parse("4e2f04df-8a39-410e-a233-26dd3686f4d1");
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
    public void InitializeCreatesIdentifiedStrictSchemaWithPatchedRuntime()
    {
        var (store, databasePath) = CreateStore();

        Assert.IsTrue(store.RuntimeSqliteVersion >= new Version(3, 51, 3));
        Assert.AreEqual(Path.GetFullPath(databasePath), store.DatabasePath);

        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());
        connection.Open();
        Assert.AreEqual(
            SqliteSimulationJobStore.ApplicationId,
            ReadInt64(connection, "PRAGMA application_id;"));
        Assert.AreEqual(
            SqliteSimulationJobStore.CurrentSchemaVersion,
            ReadInt64(connection, "PRAGMA user_version;"));
        Assert.AreEqual(
            3L,
            ReadInt64(
                connection,
                """
                SELECT COUNT(*)
                FROM pragma_table_list
                WHERE schema = 'main'
                  AND name IN ('schema_migrations', 'jobs', 'evidence')
                  AND strict = 1;
                """));
        Assert.AreEqual(
            "delete",
            Convert.ToString(
                ReadScalar(connection, "PRAGMA journal_mode;"),
                CultureInfo.InvariantCulture)?.ToLowerInvariant());
    }

    [TestMethod]
    public void CreateIsIdempotentOnlyForTheSameSimulationPlan()
    {
        var (store, _) = CreateStore();
        var firstId = Guid.Parse("77f60a28-72a8-4c90-a92d-aa99a7edfc20");
        var duplicateId = Guid.Parse("54be1e27-fd9e-43fa-9a1f-88c5b18f4eef");

        var first = store.CreateOrGetJob(
            firstId,
            "request-idempotency",
            RenewalStage.Deployment,
            testStart);
        var duplicate = store.CreateOrGetJob(
            duplicateId,
            "request-idempotency",
            RenewalStage.Deployment,
            testStart.AddMinutes(1));

        Assert.AreEqual(firstId, first.JobId);
        Assert.AreEqual(first, duplicate);
        Assert.AreEqual(RenewalStage.Deployment, first.FailureStage);
        Assert.ThrowsExactly<SimulationIdempotencyConflictException>(
            () => store.CreateOrGetJob(
                Guid.Parse("145d9ef1-f9a0-4938-be62-e2617ef3314d"),
                "request-idempotency",
                RenewalStage.Verification,
                testStart.AddMinutes(2)));
    }

    [TestMethod]
    public void StoreDefendsSingleActiveJobInvariant()
    {
        var (store, databasePath) = CreateStore();
        _ = store.CreateOrGetJob(
            Guid.Parse("4e006f74-84d7-427b-91f1-17d6e671ff40"),
            "request-active-first",
            null,
            testStart);

        Assert.ThrowsExactly<SimulationJobAlreadyActiveException>(
            () => store.CreateOrGetJob(
                Guid.Parse("abeb291a-5bd8-49cf-a06f-d69a8ecbbf3b"),
                "request-active-second",
                null,
                testStart.AddMinutes(1)));

        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());
        connection.Open();
        Assert.AreEqual(
            1L,
            ReadInt64(
                connection,
                """
                SELECT COUNT(*)
                FROM sqlite_schema
                WHERE type = 'index'
                  AND name = 'ux_jobs_single_active';
                """));
    }

    [TestMethod]
    public async Task ClaimQueuedJobIsAtomicAcrossStoreInstances()
    {
        var (firstStore, databasePath) = CreateStore();
        var secondStore = new SqliteSimulationJobStore(databasePath);
        secondStore.Initialize(testStart);
        var jobId = Guid.Parse("2b385e90-51d5-470e-9dda-c947b28e4b69");
        _ = firstStore.CreateOrGetJob(
            jobId,
            "request-atomic-claim",
            null,
            testStart);

        using var start = new ManualResetEventSlim(initialState: false);
        var firstClaimTask = Task.Run(
            () =>
            {
                start.Wait();
                return firstStore.TryClaimNextQueuedJob(
                    Guid.Parse("f0bfd595-abd7-435e-a5a7-4fb1b74b76e4"),
                    testStart.AddMinutes(1));
            });
        var secondClaimTask = Task.Run(
            () =>
            {
                start.Wait();
                return secondStore.TryClaimNextQueuedJob(
                    Guid.Parse("464c3bb7-8099-407f-bd1b-8c3a37b375b2"),
                    testStart.AddMinutes(1));
            });

        start.Set();
        var claims = await Task.WhenAll(firstClaimTask, secondClaimTask);

        Assert.AreEqual(1, claims.Count(static claim => claim is not null));
        Assert.AreEqual(jobId, claims.Single(static claim => claim is not null)!.JobId);
        Assert.AreEqual(
            SimulationJobStatus.Running,
            firstStore.FindJob(jobId)?.Status);
    }

    [TestMethod]
    public void SuccessfulCompletionRequiresVerificationAndCleanupInOrder()
    {
        var (store, _) = CreateStore();
        var jobId = CreateAndClaim(store, "request-success-proof");

        foreach (var stage in RenewalPipeline.Stages.Take(6))
        {
            AppendSucceeded(store, jobId, stage);
        }

        Assert.ThrowsExactly<InvalidOperationException>(
            () => store.CompleteJob(
                jobId,
                executionEpoch,
                SimulationJobStatus.Succeeded,
                testStart.AddHours(1),
                "simulation.succeeded",
                "The simulated renewal succeeded."));

        AppendSucceeded(store, jobId, RenewalStage.Verification);
        Assert.ThrowsExactly<InvalidOperationException>(
            () => store.CompleteJob(
                jobId,
                executionEpoch,
                SimulationJobStatus.Succeeded,
                testStart.AddHours(1),
                "simulation.succeeded",
                "The simulated renewal succeeded."));

        AppendSucceeded(store, jobId, RenewalStage.Cleanup);
        store.CompleteJob(
            jobId,
            executionEpoch,
            SimulationJobStatus.Succeeded,
            testStart.AddHours(1),
            "simulation.succeeded",
            "The simulated renewal succeeded.");

        var details = store.FindJobWithEvidence(jobId);
        Assert.IsNotNull(details);
        Assert.AreEqual(SimulationJobStatus.Succeeded, details.Job.Status);
        Assert.AreEqual(testStart.AddHours(1), details.Job.CompletedAtUtc);
        Assert.HasCount(9, details.Evidence);
        CollectionAssert.AreEqual(
            RenewalPipeline.Stages.ToArray(),
            details.Evidence
                .Where(static evidence => evidence.Kind == SimulationEvidenceKind.Stage)
                .Select(static evidence => evidence.Stage!.Value)
                .ToArray());
        Assert.AreEqual(
            SimulationEvidenceKind.Terminal,
            details.Evidence[^1].Kind);
    }

    [TestMethod]
    public void FailedCompletionRequiresMatchingOrderedStageEvidence()
    {
        var (store, _) = CreateStore();
        var jobId = CreateAndClaim(store, "request-failure-proof");
        AppendSucceeded(store, jobId, RenewalStage.Preflight);
        store.AppendStageEvidence(
            jobId,
            executionEpoch,
            RenewalStage.Order,
            RenewalStageOutcome.Failed,
            testStart.AddMinutes(2),
            "simulation.test_failure",
            "A deterministic failure was injected.");

        Assert.ThrowsExactly<InvalidOperationException>(
            () => store.CompleteJob(
                jobId,
                executionEpoch,
                SimulationJobStatus.Cancelled,
                testStart.AddMinutes(3),
                "simulation.cancelled",
                "The simulated renewal was cancelled."));

        store.CompleteJob(
            jobId,
            executionEpoch,
            SimulationJobStatus.Failed,
            testStart.AddMinutes(3),
            "simulation.failed",
            "The simulated renewal failed.");
        Assert.AreEqual(
            SimulationJobStatus.Failed,
            store.FindJob(jobId)?.Status);
    }

    [TestMethod]
    public void NewStoreInitializationRecoversRunningJobAsInterrupted()
    {
        var (firstStore, databasePath) = CreateStore();
        var jobId = CreateAndClaim(firstStore, "request-recovery");
        AppendSucceeded(firstStore, jobId, RenewalStage.Preflight);
        var recoveryTime = testStart.AddHours(2);

        var restartedStore = new SqliteSimulationJobStore(databasePath);
        restartedStore.Initialize(recoveryTime);

        var details = restartedStore.FindJobWithEvidence(jobId);
        Assert.IsNotNull(details);
        Assert.AreEqual(SimulationJobStatus.Interrupted, details.Job.Status);
        Assert.AreEqual(recoveryTime, details.Job.CompletedAtUtc);
        Assert.AreEqual(SimulationEvidenceKind.Recovery, details.Evidence[^1].Kind);
        Assert.AreEqual(
            "persistence.recovered_interrupted",
            details.Evidence[^1].Code);
        Assert.AreEqual(recoveryTime, details.Evidence[^1].RecordedAtUtc);
    }

    [TestMethod]
    public void RepeatedInitializeOnSameStoreDoesNotInterruptItsRunningJob()
    {
        var (store, _) = CreateStore();
        var jobId = CreateAndClaim(store, "request-repeat-initialize");

        store.Initialize(testStart.AddHours(4));

        var details = store.FindJobWithEvidence(jobId);
        Assert.IsNotNull(details);
        Assert.AreEqual(SimulationJobStatus.Running, details.Job.Status);
        Assert.IsEmpty(details.Evidence);
    }

    [TestMethod]
    public void QueuedJobSurvivesNewStoreInitialization()
    {
        var (firstStore, databasePath) = CreateStore();
        var jobId = Guid.Parse("130c731f-7a0b-4ea5-8821-2d5b31c6c529");
        _ = firstStore.CreateOrGetJob(
            jobId,
            "request-queued-restart",
            RenewalStage.Issuance,
            testStart);

        var restartedStore = new SqliteSimulationJobStore(databasePath);
        restartedStore.Initialize(testStart.AddHours(3));

        var details = restartedStore.GetLatestJobWithEvidence();
        Assert.IsNotNull(details);
        Assert.AreEqual(jobId, details.Job.JobId);
        Assert.AreEqual(RenewalStage.Issuance, details.Job.FailureStage);
        Assert.AreEqual(SimulationJobStatus.Queued, details.Job.Status);
        Assert.IsEmpty(details.Evidence);
    }

    [TestMethod]
    public void LatestJobUsesDurableInsertionOrderWhenClockMovesBackward()
    {
        var (store, _) = CreateStore();
        var olderSuccessId =
            Guid.Parse("19cc27de-438e-4573-afc8-41f57184dfc3");
        var futureTimestamp = testStart.AddDays(1);
        _ = store.CreateOrGetJob(
            olderSuccessId,
            "request-before-clock-rollback",
            null,
            futureTimestamp);
        _ = store.TryClaimNextQueuedJob(
            executionEpoch,
            futureTimestamp.AddMinutes(1));
        foreach (var stage in RenewalPipeline.Stages)
        {
            store.AppendStageEvidence(
                olderSuccessId,
                executionEpoch,
                stage,
                RenewalStageOutcome.Succeeded,
                futureTimestamp.AddMinutes(2 + (int)stage),
                "simulation.stage_succeeded",
                $"The simulated {stage} stage completed.");
        }

        store.CompleteJob(
            olderSuccessId,
            executionEpoch,
            SimulationJobStatus.Succeeded,
            futureTimestamp.AddHours(1),
            "simulation.succeeded",
            "The simulated renewal succeeded.");

        var newerFailureId =
            Guid.Parse("26cf9a16-b9de-4675-9cd8-afb1d559991f");
        _ = store.CreateOrGetJob(
            newerFailureId,
            "request-after-clock-rollback",
            RenewalStage.Preflight,
            testStart);
        _ = store.TryClaimNextQueuedJob(
            executionEpoch,
            testStart.AddMinutes(1));
        store.AppendStageEvidence(
            newerFailureId,
            executionEpoch,
            RenewalStage.Preflight,
            RenewalStageOutcome.Failed,
            testStart.AddMinutes(2),
            "simulation.test_failure",
            "A deterministic failure was injected.");
        store.CompleteJob(
            newerFailureId,
            executionEpoch,
            SimulationJobStatus.Failed,
            testStart.AddMinutes(3),
            "simulation.failed",
            "The simulated renewal failed.");

        var latest = store.GetLatestJobWithEvidence();

        Assert.IsNotNull(latest);
        Assert.AreEqual(newerFailureId, latest.Job.JobId);
        Assert.AreEqual(SimulationJobStatus.Failed, latest.Job.Status);
    }

    [TestMethod]
    public void WrongExecutionEpochCannotAppendStageEvidence()
    {
        var (store, _) = CreateStore();
        var jobId = CreateAndClaim(store, "request-wrong-epoch-append");
        var wrongEpoch =
            Guid.Parse("cb393ef7-e2f6-4cba-8e28-02656e7e0e6b");

        Assert.ThrowsExactly<InvalidOperationException>(
            () => store.AppendStageEvidence(
                jobId,
                wrongEpoch,
                RenewalStage.Preflight,
                RenewalStageOutcome.Succeeded,
                testStart.AddMinutes(2),
                "simulation.stage_succeeded",
                "The simulated Preflight stage completed."));

        Assert.IsEmpty(store.ReadEvidence(jobId));
        Assert.AreEqual(
            SimulationJobStatus.Running,
            store.FindJob(jobId)?.Status);
    }

    [TestMethod]
    public void WrongExecutionEpochCannotCompleteProvenJob()
    {
        var (store, _) = CreateStore();
        var jobId = CreateAndClaim(store, "request-wrong-epoch-complete");
        foreach (var stage in RenewalPipeline.Stages)
        {
            AppendSucceeded(store, jobId, stage);
        }

        Assert.ThrowsExactly<InvalidOperationException>(
            () => store.CompleteJob(
                jobId,
                Guid.Parse("6e537fc6-13d7-4bb0-b332-55e43d006d51"),
                SimulationJobStatus.Succeeded,
                testStart.AddHours(1),
                "simulation.succeeded",
                "The simulated renewal succeeded."));

        var details = store.FindJobWithEvidence(jobId);
        Assert.IsNotNull(details);
        Assert.AreEqual(SimulationJobStatus.Running, details.Job.Status);
        Assert.HasCount(RenewalPipeline.Stages.Count, details.Evidence);
        Assert.IsFalse(
            details.Evidence.Any(
                static item => item.Kind == SimulationEvidenceKind.Terminal));
    }

    [TestMethod]
    public void ConstructorRejectsRelativeAndUncPaths()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => new SqliteSimulationJobStore("relative.db"));
        Assert.ThrowsExactly<ArgumentException>(
            () => new SqliteSimulationJobStore(
                @"\\server\share\certbaton.db"));
    }

    private (SqliteSimulationJobStore Store, string DatabasePath) CreateStore()
    {
        var directory = Directory
            .CreateTempSubdirectory("CertBaton.UnitTests-")
            .FullName;
        testDirectories.Add(directory);
        var databasePath = Path.Combine(directory, "simulation.db");
        var store = new SqliteSimulationJobStore(databasePath);
        store.Initialize(testStart);
        return (store, databasePath);
    }

    private static Guid CreateAndClaim(
        SqliteSimulationJobStore store,
        string requestKey)
    {
        var jobId = Guid.NewGuid();
        _ = store.CreateOrGetJob(jobId, requestKey, null, testStart);
        var claim = store.TryClaimNextQueuedJob(
            executionEpoch,
            testStart.AddMinutes(1));
        Assert.IsNotNull(claim);
        Assert.AreEqual(jobId, claim.JobId);
        return jobId;
    }

    private static void AppendSucceeded(
        SqliteSimulationJobStore store,
        Guid jobId,
        RenewalStage stage)
    {
        store.AppendStageEvidence(
            jobId,
            executionEpoch,
            stage,
            RenewalStageOutcome.Succeeded,
            testStart.AddMinutes(2 + (int)stage),
            "simulation.stage_succeeded",
            $"The simulated {stage} stage completed.");
    }

    private static object? ReadScalar(
        SqliteConnection connection,
        string commandText)
    {
        using var command = connection.CreateCommand();
        command.CommandText = commandText;
        return command.ExecuteScalar();
    }

    private static long ReadInt64(
        SqliteConnection connection,
        string commandText) =>
        Convert.ToInt64(
            ReadScalar(connection, commandText),
            CultureInfo.InvariantCulture);
}
