using System.Security.Cryptography;
using System.Text;
using CertBaton.Application.Live;
using CertBaton.Application.Security;
using CertBaton.Application.Verification;
using CertBaton.Contracts;
using CertBaton.Domain.Connections;
using CertBaton.Domain.Deployments;
using CertBaton.Domain.Operations;
using CertBaton.Domain.Scheduling;
using CertBaton.Domain.Targets;
using CertBaton.Persistence.Sqlite;
using CertBaton.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertBaton.UnitTests;

[TestClass]
[DoNotParallelize]
public sealed class LiveRenewalCoordinatorTests
{
    private static readonly DateTimeOffset TestNow = new(
        2026,
        7,
        31,
        20,
        0,
        0,
        TimeSpan.Zero);
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
    public async Task ManualStartIsIdempotentAndExecutesOnlyOnce()
    {
        var store = CreateStore();
        var fixture = SaveSyntheticEnrollment(store);
        var executor = new FakeLiveRenewalExecutor(
            static (operationId, _, _, _) => Task.FromResult(
                CreateFailedResult(operationId, "acme.order_failed")));
        using var coordinator = CreateCoordinator(store, executor);
        var payload = new RenewalStartPayload(
            fixture.TargetId.Value,
            Guid.CreateVersion7());

        var first = await coordinator.StartAsync(
            payload,
            "S-1-5-21-1000",
            CancellationToken.None);
        var retry = await coordinator.StartAsync(
            payload,
            "S-1-5-21-1000",
            CancellationToken.None);

        Assert.AreEqual(first.OperationId, retry.OperationId);
        Assert.AreEqual("queued", first.Status);
        Assert.AreEqual(0, executor.InvocationCount);

        await coordinator.StartAsync(CancellationToken.None);
        try
        {
            var completed = await WaitForStatusAsync(
                coordinator,
                first.OperationId,
                "failed");

            Assert.AreEqual("acme.order_failed", completed.FailureCode);
            Assert.AreEqual(1, executor.InvocationCount);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task SuccessfulExecutionProducesValidVerifiedSnapshot()
    {
        const string certificateSha256 =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const string publicKeySha256 =
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        var store = CreateStore();
        var fixture = SaveSyntheticEnrollment(
            store,
            renewBeforeDays: 90);
        var privateKeyReference = new SecretReference(Guid.CreateVersion7());
        var notBeforeUtc = TestNow.AddMinutes(-5);
        var notAfterUtc = TestNow.AddDays(90);
        var executor = new FakeLiveRenewalExecutor(
            (operationId, executionEpoch, _, _) =>
            {
                _ = store.CreateOrGetCertificateArtifact(
                    new CertificateArtifact(
                        new CertificateArtifactId(operationId.Value),
                        operationId,
                        new Sha256Digest(certificateSha256),
                        new Sha256Digest(publicKeySha256),
                        privateKeyReference.ToString(),
                        notBeforeUtc,
                        notAfterUtc,
                        CertificateArtifactStatus.Issued,
                        TestNow));
                _ = store.AppendOperationEvidence(
                    operationId,
                    OperationEvidenceKind.Verification,
                    stage: null,
                    OperationEvidenceOutcome.Succeeded,
                    TestNow,
                    "tls.all_names_verified",
                    "The synthetic public TLS verification succeeded.");
                _ = store.AppendOperationEvidence(
                    operationId,
                    OperationEvidenceKind.Cleanup,
                    stage: null,
                    OperationEvidenceOutcome.Succeeded,
                    TestNow,
                    "challenge.cleanup_complete",
                    "The synthetic HTTP-01 challenge cleanup succeeded.");
                _ = store.CreateOrGetOperationIntent(
                    new OperationIntent(
                        OperationIntentId.Create(),
                        operationId,
                        sequence: 1,
                        OperationIntentKind.Commit,
                        $"synthetic-commit:{operationId}",
                        OperationIntentStatus.Applied,
                        TestNow,
                        TestNow));
                return Task.FromResult(
                    new LiveRenewalResult(
                        operationId.Value,
                        LiveRenewalStatus.Succeeded,
                        failureCode: null,
                        challengeCleanupVerified: true,
                        publicTlsVerified: true,
                        activationAttempted: true,
                        rollbackAttempted: false,
                        rollbackSucceeded: false,
                        certificateSha256,
                        publicKeySha256,
                        notBeforeUtc,
                        notAfterUtc,
                        privateKeyReference,
                        TlsTrustPolicy.ExpectedLeaf));
            });
        using var coordinator = CreateCoordinator(store, executor);
        await coordinator.StartAsync(CancellationToken.None);
        try
        {
            var started = await coordinator.StartAsync(
                new RenewalStartPayload(
                    fixture.TargetId.Value,
                    Guid.CreateVersion7()),
                "S-1-5-21-1000",
                CancellationToken.None);
            var completed = await WaitForStatusAsync(
                coordinator,
                started.OperationId,
                "succeeded");

            Assert.IsTrue(completed.TryValidate(out var validationError), validationError);
            Assert.AreEqual(certificateSha256, completed.CertificateLeafSha256);
            Assert.IsTrue(completed.PublicTlsVerified);
            Assert.IsTrue(completed.ChallengeCleanupVerified);
            Assert.IsTrue(
                completed.Evidence.Any(
                    static evidence =>
                        evidence.Category == "verification" &&
                        evidence.Outcome == "succeeded"));
            Assert.IsTrue(
                completed.Evidence.Any(
                    static evidence =>
                        evidence.Category == "cleanup" &&
                        evidence.Outcome == "succeeded"));
            Assert.AreEqual(
                CertificateArtifactStatus.Deployed,
                store.FindCertificateArtifact(
                    new OperationId(started.OperationId))?.Status);
            Assert.AreEqual(1, executor.InvocationCount);
            var rescheduled = store.FindRenewalPolicyByTarget(
                fixture.TargetId);
            Assert.IsNotNull(rescheduled?.NextDueAtUtc);
            Assert.IsGreaterThan(
                TestNow.AddDays(59),
                rescheduled.NextDueAtUtc.Value,
                "Renew-before must be capped to one third of observed certificate lifetime.");
            Assert.IsLessThan(
                TestNow.AddDays(61),
                rescheduled.NextDueAtUtc.Value);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task ShortLivedCertificateUsesOneThirdLifetimeRenewalBoundary()
    {
        var store = CreateStore();
        var fixture = SaveSyntheticEnrollment(store, renewBeforeDays: 90);
        var notBeforeUtc = TestNow.AddMinutes(-5);
        var notAfterUtc = notBeforeUtc.AddDays(7);
        var executor = CreateSuccessfulExecutor(
            store,
            notBeforeUtc,
            notAfterUtc);
        using var coordinator = CreateCoordinator(store, executor);
        await coordinator.StartAsync(CancellationToken.None);
        try
        {
            var started = await coordinator.StartAsync(
                new RenewalStartPayload(
                    fixture.TargetId.Value,
                    Guid.CreateVersion7()),
                "S-1-5-21-1000",
                CancellationToken.None);
            _ = await WaitForStatusAsync(
                coordinator,
                started.OperationId,
                "succeeded");

            var policy = store.FindRenewalPolicyByTarget(fixture.TargetId);
            Assert.IsNotNull(policy?.NextDueAtUtc);
            Assert.AreEqual(
                notAfterUtc - TimeSpan.FromTicks(
                    (notAfterUtc - notBeforeUtc).Ticks / 3),
                policy.NextDueAtUtc.Value);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task PastRenewalBoundaryUsesConfiguredCheckIntervalRetry()
    {
        var store = CreateStore();
        var fixture = SaveSyntheticEnrollment(store, renewBeforeDays: 90);
        var notBeforeUtc = TestNow.AddHours(-23);
        var notAfterUtc = TestNow.AddHours(1);
        var executor = CreateSuccessfulExecutor(
            store,
            notBeforeUtc,
            notAfterUtc);
        using var coordinator = CreateCoordinator(store, executor);
        await coordinator.StartAsync(CancellationToken.None);
        try
        {
            var started = await coordinator.StartAsync(
                new RenewalStartPayload(
                    fixture.TargetId.Value,
                    Guid.CreateVersion7()),
                "S-1-5-21-1000",
                CancellationToken.None);
            _ = await WaitForStatusAsync(
                coordinator,
                started.OperationId,
                "succeeded");

            var policy = store.FindRenewalPolicyByTarget(fixture.TargetId);
            Assert.IsNotNull(policy?.NextDueAtUtc);
            Assert.AreEqual(TestNow.AddMinutes(15), policy.NextDueAtUtc.Value);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task ExecutorExceptionCompletesOperationAsFailed()
    {
        var store = CreateStore();
        var fixture = SaveSyntheticEnrollment(store);
        var executor = new FakeLiveRenewalExecutor(
            static (_, _, _, _) => Task.FromException<LiveRenewalResult>(
                new InvalidOperationException("Synthetic executor failure.")));
        using var coordinator = CreateCoordinator(store, executor);
        await coordinator.StartAsync(CancellationToken.None);
        try
        {
            var started = await coordinator.StartAsync(
                new RenewalStartPayload(
                    fixture.TargetId.Value,
                    Guid.CreateVersion7()),
                "S-1-5-21-1000",
                CancellationToken.None);
            var completed = await WaitForStatusAsync(
                coordinator,
                started.OperationId,
                "failed");

            Assert.AreEqual("service.execution_failed", completed.FailureCode);
            Assert.IsTrue(
                completed.Evidence.Any(
                    static evidence =>
                        evidence.Category == "terminal" &&
                        evidence.Code == "service.execution_failed"));
            Assert.AreEqual(1, executor.InvocationCount);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task RestartInterruptsPersistedPreActivationOperation()
    {
        var store = CreateStore();
        var fixture = SaveSyntheticEnrollment(store);
        var running = CreatePersistedRunningOperation(store, fixture.TargetId);
        var executor = new FakeLiveRenewalExecutor(
            static (operationId, _, _, _) => Task.FromResult(
                CreateFailedResult(operationId, "unexpected.execution")),
            static (operationId, _, _, _) => Task.FromResult(
                CreateFailedResult(
                    operationId,
                    "recovery.unactivated_aborted")));
        using var coordinator = CreateCoordinator(store, executor);

        await coordinator.StartAsync(CancellationToken.None);
        try
        {
            var recovered = await WaitForStatusAsync(
                coordinator,
                running.Id.Value,
                "interrupted");

            Assert.AreEqual(
                "recovery.unactivated_aborted",
                recovered.FailureCode);
            Assert.AreEqual(0, executor.InvocationCount);
            Assert.AreEqual(1, executor.RecoveryInvocationCount);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task RestartRequiresRollbackForPersistedPostActivationOperation()
    {
        var store = CreateStore();
        var fixture = SaveSyntheticEnrollment(store);
        var running = CreatePersistedRunningOperation(store, fixture.TargetId);
        _ = store.CreateOrGetOperationIntent(
            new OperationIntent(
                OperationIntentId.Create(),
                running.Id,
                sequence: 1,
                OperationIntentKind.Activate,
                $"activate:{running.Id.Value:N}",
                OperationIntentStatus.Planned,
                TestNow));
        var executor = new FakeLiveRenewalExecutor(
            static (operationId, _, _, _) => Task.FromResult(
                CreateFailedResult(operationId, "unexpected.execution")),
            static (operationId, _, _, _) => Task.FromResult(
                CreateRollbackRequiredResult(operationId)));
        using var coordinator = CreateCoordinator(store, executor);

        await coordinator.StartAsync(CancellationToken.None);
        try
        {
            var recovered = await WaitForStatusAsync(
                coordinator,
                running.Id.Value,
                "rollback-required");

            Assert.AreEqual("recovery.rollback_failed", recovered.FailureCode);
            Assert.IsNull(recovered.CompletedAtUtc);
            Assert.AreEqual(0, executor.InvocationCount);
            Assert.AreEqual(1, executor.RecoveryInvocationCount);
        }
        finally
        {
            await coordinator.StopAsync(CancellationToken.None);
        }
    }

    [TestMethod]
    public async Task AutomaticSchedulingDoesNotReexecuteTerminalRequest()
    {
        var dueAtUtc = TestNow.AddMinutes(-5);
        var store = CreateStore();
        var fixture = SaveSyntheticEnrollment(store, dueAtUtc);
        var firstExecutor = new FakeLiveRenewalExecutor(
            static (operationId, _, _, _) => Task.FromResult(
                CreateFailedResult(operationId, "acme.order_failed")));
        using (var firstCoordinator = CreateCoordinator(store, firstExecutor))
        {
            await firstCoordinator.StartAsync(CancellationToken.None);
            try
            {
                var operationId = await firstExecutor.FirstInvocation.Task.WaitAsync(
                    TimeSpan.FromSeconds(5));
                _ = await WaitForStatusAsync(
                    firstCoordinator,
                    operationId.Value,
                    "failed");
            }
            finally
            {
                await firstCoordinator.StopAsync(CancellationToken.None);
            }
        }

        Assert.AreEqual(1, firstExecutor.InvocationCount);
        var rescheduled = store.FindEnabledRenewalPolicy(fixture.TargetId);
        Assert.IsNotNull(rescheduled);
        store.SaveRenewalPolicy(
            new RenewalPolicy(
                rescheduled.Id,
                rescheduled.TargetId,
                rescheduled.RenewBeforeDays,
                rescheduled.CheckIntervalMinutes,
                rescheduled.Enabled,
                dueAtUtc,
                rescheduled.CreatedAtUtc,
                TestNow));

        var restartExecutor = new FakeLiveRenewalExecutor(
            static (operationId, _, _, _) => Task.FromResult(
                CreateFailedResult(operationId, "unexpected.execution")));
        using var restartedCoordinator = CreateCoordinator(store, restartExecutor);
        await restartedCoordinator.StartAsync(CancellationToken.None);
        try
        {
            await WaitForAsync(
                () => store.FindEnabledRenewalPolicy(fixture.TargetId)?.NextDueAtUtc >
                    TestNow,
                "The already-terminal automatic request was not rescheduled.");
            await Task.Delay(100);

            Assert.AreEqual(0, restartExecutor.InvocationCount);
            Assert.IsEmpty(store.ListActiveOperations(10));
        }
        finally
        {
            await restartedCoordinator.StopAsync(CancellationToken.None);
        }
    }

    private SqliteProductionStore CreateStore()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "CertBaton.UnitTests",
            $"live-renewal-{Guid.CreateVersion7():N}");
        Directory.CreateDirectory(directory);
        testDirectories.Add(directory);
        var store = new SqliteProductionStore(Path.Combine(directory, "state.db"));
        store.Initialize(TestNow);
        return store;
    }

    private static SyntheticEnrollment SaveSyntheticEnrollment(
        SqliteProductionStore store,
        DateTimeOffset? nextDueAtUtc = null,
        int renewBeforeDays = 20)
    {
        var rawHostKey = SHA256.HashData(
            Encoding.UTF8.GetBytes("synthetic-ed25519-host-key"));
        var fingerprint =
            "SHA256:" +
            Convert.ToBase64String(SHA256.HashData(rawHostKey)).TrimEnd('=');
        var connection = new ConnectionProfile(
            ConnectionId.Create(),
            "Synthetic SSH connection",
            new ConnectionEndpoint("ssh.example.test"),
            "certbaton",
            Guid.CreateVersion7().ToString("D"),
            "ssh-ed25519",
            fingerprint,
            TestNow,
            TestNow,
            enabled: true,
            rawHostKey);
        var target = new CertificateTarget(
            TargetId.Create(),
            connection.Id,
            "Synthetic website",
            new TargetDnsName("www.example.test"),
            [],
            TargetLifecycleStatus.Ready,
            TestNow,
            TestNow);
        var deployment = new DeploymentPlan(
            DeploymentPlanId.Create(),
            target.Id,
            DeploymentKind.Nginx,
            new RemotePath("/srv/www/challenges"),
            new RemotePath("/var/lib/certbaton/incoming"),
            new RemotePath("/etc/nginx/tls/fullchain.pem"),
            new RemotePath("/etc/nginx/tls/privkey.pem"),
            TestNow,
            TestNow);
        var policy = new RenewalPolicy(
            RenewalPolicyId.Create(),
            target.Id,
            renewBeforeDays,
            checkIntervalMinutes: 15,
            enabled: true,
            nextDueAtUtc,
            TestNow,
            TestNow);
        var issuance = new TargetIssuanceProfile(
            target.Id,
            new Uri(LiveContractValues.LetsEncryptStagingDirectory),
            new AcmeContactUri("operator@example.test"),
            termsAccepted: true,
            TestNow,
            Guid.CreateVersion7().ToString("D"),
            accountUri: null,
            TestNow,
            TestNow);
        store.SaveEnrollment(
            new TargetEnrollment(
                EnrollmentId.Create(),
                connection,
                target,
                deployment,
                policy,
                issuance,
                TestNow));
        return new SyntheticEnrollment(target.Id);
    }

    private static RenewalOperation CreatePersistedRunningOperation(
        SqliteProductionStore store,
        TargetId targetId)
    {
        var queued = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                targetId,
                $"persisted:{Guid.CreateVersion7():N}",
                TestNow));
        return store.TryStartOperation(
                queued.Id,
                Guid.CreateVersion7(),
                TestNow)
            ?? throw new InvalidOperationException(
                "The synthetic persisted operation could not be claimed.");
    }

    private static LiveRenewalCoordinator CreateCoordinator(
        SqliteProductionStore store,
        ILiveRenewalExecutor executor) =>
        new(
            store,
            executor,
            new FixedTimeProvider(TestNow),
            NullLogger<LiveRenewalCoordinator>.Instance);

    private static FakeLiveRenewalExecutor CreateSuccessfulExecutor(
        SqliteProductionStore store,
        DateTimeOffset notBeforeUtc,
        DateTimeOffset notAfterUtc) =>
        new(
            (operationId, executionEpoch, _, _) =>
            {
                const string certificateSha256 =
                    "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
                const string publicKeySha256 =
                    "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
                var privateKeyReference =
                    new SecretReference(Guid.CreateVersion7());
                _ = store.CreateOrGetCertificateArtifact(
                    new CertificateArtifact(
                        new CertificateArtifactId(operationId.Value),
                        operationId,
                        new Sha256Digest(certificateSha256),
                        new Sha256Digest(publicKeySha256),
                        privateKeyReference.ToString(),
                        notBeforeUtc,
                        notAfterUtc,
                        CertificateArtifactStatus.Issued,
                        TestNow));
                _ = store.AppendOperationEvidence(
                    operationId,
                    OperationEvidenceKind.Verification,
                    stage: null,
                    OperationEvidenceOutcome.Succeeded,
                    TestNow,
                    "tls.all_names_verified",
                    "Every configured DNS name was verified.");
                _ = store.AppendOperationEvidence(
                    operationId,
                    OperationEvidenceKind.Cleanup,
                    stage: null,
                    OperationEvidenceOutcome.Succeeded,
                    TestNow,
                    "challenge.cleanup_complete",
                    "Every temporary challenge was removed.");
                _ = store.CreateOrGetOperationIntent(
                    new OperationIntent(
                        OperationIntentId.Create(),
                        operationId,
                        sequence: 1,
                        OperationIntentKind.Commit,
                        $"synthetic-commit:{operationId}",
                        OperationIntentStatus.Applied,
                        TestNow,
                        TestNow));
                return Task.FromResult(
                    new LiveRenewalResult(
                        operationId.Value,
                        LiveRenewalStatus.Succeeded,
                        failureCode: null,
                        challengeCleanupVerified: true,
                        publicTlsVerified: true,
                        activationAttempted: true,
                        rollbackAttempted: false,
                        rollbackSucceeded: false,
                        certificateSha256,
                        publicKeySha256,
                        notBeforeUtc,
                        notAfterUtc,
                        privateKeyReference,
                        TlsTrustPolicy.ExpectedLeaf));
            });

    private static LiveRenewalResult CreateFailedResult(
        OperationId operationId,
        string failureCode) =>
        new(
            operationId.Value,
            LiveRenewalStatus.Failed,
            failureCode,
            challengeCleanupVerified: false,
            publicTlsVerified: false,
            activationAttempted: false,
            rollbackAttempted: false,
            rollbackSucceeded: false,
            certificateLeafSha256: null,
            publicKeySha256: null,
            notBeforeUtc: null,
            notAfterUtc: null,
            certificatePrivateKeyReference: null,
            TlsTrustPolicy.ExpectedLeaf);

    private static LiveRenewalResult CreateRollbackRequiredResult(
        OperationId operationId) =>
        new(
            operationId.Value,
            LiveRenewalStatus.RollbackRequired,
            "recovery.rollback_failed",
            challengeCleanupVerified: false,
            publicTlsVerified: false,
            activationAttempted: true,
            rollbackAttempted: true,
            rollbackSucceeded: false,
            certificateLeafSha256: null,
            publicKeySha256: null,
            notBeforeUtc: null,
            notAfterUtc: null,
            certificatePrivateKeyReference: null,
            TlsTrustPolicy.ExpectedLeaf);

    private static async Task<RenewalOperationSnapshot> WaitForStatusAsync(
        LiveRenewalCoordinator coordinator,
        Guid operationId,
        string expectedStatus)
    {
        RenewalOperationSnapshot? last = null;
        for (var attempt = 0; attempt < 500; attempt++)
        {
            last = coordinator.Find(operationId);
            if (last?.Status == expectedStatus)
            {
                return last;
            }

            await Task.Delay(10);
        }

        Assert.Fail(
            $"Operation {operationId:D} did not reach {expectedStatus}; last status was {last?.Status ?? "missing"}, failure was {last?.FailureCode ?? "missing"}, evidence was {string.Join(',', last?.Evidence.Select(static item => item.Code) ?? [])}.");
        throw new InvalidOperationException("Unreachable assertion fallback.");
    }

    private static async Task WaitForAsync(
        Func<bool> condition,
        string timeoutMessage)
    {
        for (var attempt = 0; attempt < 500; attempt++)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(10);
        }

        Assert.Fail(timeoutMessage);
    }

    private sealed record SyntheticEnrollment(TargetId TargetId);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class FakeLiveRenewalExecutor(
        Func<
            OperationId,
            Guid,
            LiveHttp01RenewalRequest,
            CancellationToken,
            Task<LiveRenewalResult>> handler,
        Func<
            OperationId,
            Guid,
            LiveHttp01RenewalRequest,
            CancellationToken,
            Task<LiveRenewalResult>>? recoveryHandler = null) : ILiveRenewalExecutor
    {
        private int invocationCount;
        private int recoveryInvocationCount;

        public int InvocationCount => Volatile.Read(ref invocationCount);

        public int RecoveryInvocationCount =>
            Volatile.Read(ref recoveryInvocationCount);

        public TaskCompletionSource<OperationId> FirstInvocation { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<OperationId> FirstRecovery { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<LiveRenewalResult> RunAsync(
            OperationId operationId,
            Guid executionEpoch,
            LiveHttp01RenewalRequest request,
            CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref invocationCount);
            _ = FirstInvocation.TrySetResult(operationId);
            return handler(
                operationId,
                executionEpoch,
                request,
                cancellationToken);
        }

        public Task<LiveRenewalResult> RecoverAsync(
            OperationId operationId,
            Guid executionEpoch,
            LiveHttp01RenewalRequest request,
            CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref recoveryInvocationCount);
            _ = FirstRecovery.TrySetResult(operationId);
            return recoveryHandler?.Invoke(
                    operationId,
                    executionEpoch,
                    request,
                    cancellationToken) ??
                Task.FromException<LiveRenewalResult>(
                    new InvalidOperationException(
                        "The test did not expect recovery execution."));
        }
    }
}
