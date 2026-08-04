using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertBaton.Application.Acme;
using CertBaton.Application.Live;
using CertBaton.Application.Remote;
using CertBaton.Application.Security;
using CertBaton.Application.Verification;
using CertBaton.Domain.Connections;
using CertBaton.Domain.Operations;
using CertBaton.Domain.Targets;
using CertBaton.Persistence.Sqlite;
using CertBaton.Service;

namespace CertBaton.UnitTests;

[TestClass]
[DoNotParallelize]
public sealed class ProductionLiveRenewalRecoveryTests
{
    private static readonly DateTimeOffset testTime =
        new(2026, 7, 31, 16, 0, 0, TimeSpan.Zero);
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
    public async Task PreparedTransactionIsAbortedAndRecoveryFailsSafely()
    {
        var fixture = CreateFixture();
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "prepared",
            active: false,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        Assert.AreEqual("recovery.unactivated_aborted", result.FailureCode);
        Assert.IsFalse(result.ActivationAttempted);
        CollectionAssert.AreEqual(
            new[] { RemoteHelperVerbV1.Status, RemoteHelperVerbV1.Abort },
            fixture.Session.HelperVerbs);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Abort,
            OperationIntentStatus.Reconciled);
    }

    [TestMethod]
    public async Task FailedPreActivationAbortRemainsBlockedAndRetryReconcilesIntent()
    {
        var fixture = CreateFixture();
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "prepared",
            active: false,
            recoveryRequired: false);
        fixture.Session.FailingVerbs.Add(RemoteHelperVerbV1.Abort);

        var blocked = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Blocked, blocked.Status);
        Assert.AreEqual("recovery.abort_required", blocked.FailureCode);
        Assert.IsFalse(blocked.ActivationAttempted);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Abort,
            OperationIntentStatus.Failed);

        _ = fixture.Session.FailingVerbs.Remove(RemoteHelperVerbV1.Abort);
        var recovered = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Failed, recovered.Status);
        Assert.AreEqual("recovery.unactivated_aborted", recovered.FailureCode);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Abort,
            OperationIntentStatus.Reconciled);
    }

    [TestMethod]
    public async Task PersistedChallengePathIsRemovedAndPlannedIntentIsReconciled()
    {
        var fixture = CreateFixture();
        var path = fixture.AddChallengeWrite(OperationIntentStatus.Planned);
        fixture.Session.StatusResult = new RemoteHelperResult(
            1,
            null,
            string.Empty,
            "{\"code\":\"helper.state_missing\"}");

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        Assert.AreEqual("recovery.transaction_missing", result.FailureCode);
        Assert.IsTrue(result.ChallengeCleanupVerified);
        CollectionAssert.AreEqual(
            new[] { path },
            fixture.Session.RemovedPaths);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.ChallengeWrite,
            OperationIntentStatus.Reconciled);
    }

    [TestMethod]
    public async Task FailedChallengeCleanupRemainsBlockedUntilRetryProvesRemoval()
    {
        var fixture = CreateFixture();
        _ = fixture.AddChallengeWrite(OperationIntentStatus.Failed);
        fixture.Session.FailRemoval = true;
        fixture.Session.StatusResult = new RemoteHelperResult(
            1,
            null,
            string.Empty,
            "{\"code\":\"helper.state_missing\"}");

        var blocked = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Blocked, blocked.Status);
        Assert.AreEqual(
            "recovery.challenge_cleanup_required",
            blocked.FailureCode);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.ChallengeWrite,
            OperationIntentStatus.Failed);

        fixture.Session.FailRemoval = false;
        var recovered = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Failed, recovered.Status);
        Assert.IsTrue(recovered.ChallengeCleanupVerified);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.ChallengeWrite,
            OperationIntentStatus.Reconciled);
    }

    [TestMethod]
    public async Task ActiveTransactionWithArtifactCleanupAndTlsEvidenceIsCommitted()
    {
        var fixture = CreateFixture();
        fixture.AddArtifactAndAggregateCleanup();
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "active",
            active: true,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Succeeded, result.Status);
        Assert.IsTrue(result.ChallengeCleanupVerified);
        Assert.IsTrue(result.PublicTlsVerified);
        Assert.IsNull(result.FailureCode);
        CollectionAssert.AreEqual(
            new[]
            {
                RemoteHelperVerbV1.Status,
                RemoteHelperVerbV1.Verify,
                RemoteHelperVerbV1.Commit,
            },
            fixture.Session.HelperVerbs);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Commit,
            OperationIntentStatus.Reconciled);
        var evidence = fixture.Store.ReadOperationEvidence(fixture.OperationId);
        Assert.IsTrue(
            evidence.Any(
                static item =>
                    item.Kind == OperationEvidenceKind.Cleanup &&
                    item.Code == "challenge.cleanup_complete" &&
                    item.Outcome == OperationEvidenceOutcome.Succeeded));
        Assert.IsTrue(
            evidence.Any(
                static item =>
                    item.Kind == OperationEvidenceKind.Verification &&
                    item.Code == "tls.all_names_verified" &&
                    item.Outcome == OperationEvidenceOutcome.Succeeded));
        Assert.IsTrue(
            evidence.Any(
                static item =>
                    item.Kind == OperationEvidenceKind.Terminal &&
                    item.Code == "renewal.succeeded" &&
                    item.Outcome == OperationEvidenceOutcome.Succeeded));
    }

    [TestMethod]
    public async Task ActiveTransactionWithTlsFailureRollsBackAndFails()
    {
        var fixture = CreateFixture();
        fixture.AddArtifactAndAggregateCleanup();
        fixture.TlsVerifier.Success = false;
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "active",
            active: true,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        Assert.AreEqual("recovery.tls_verify_failed", result.FailureCode);
        Assert.IsTrue(result.ActivationAttempted);
        Assert.IsTrue(result.RollbackAttempted);
        Assert.IsTrue(result.RollbackSucceeded);
        CollectionAssert.AreEqual(
            new[]
            {
                RemoteHelperVerbV1.Status,
                RemoteHelperVerbV1.Verify,
                RemoteHelperVerbV1.Rollback,
                RemoteHelperVerbV1.Abort,
            },
            fixture.Session.HelperVerbs);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Rollback,
            OperationIntentStatus.Reconciled);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Abort,
            OperationIntentStatus.Reconciled);
    }

    [TestMethod]
    public async Task ActiveTransactionWithTlsAndRollbackFailuresRequiresRollback()
    {
        var fixture = CreateFixture();
        fixture.AddArtifactAndAggregateCleanup();
        fixture.TlsVerifier.Success = false;
        fixture.Session.FailingVerbs.Add(RemoteHelperVerbV1.Rollback);
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "active",
            active: true,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.RollbackRequired, result.Status);
        Assert.AreEqual("recovery.rollback_failed", result.FailureCode);
        Assert.IsTrue(result.ActivationAttempted);
        Assert.IsTrue(result.RollbackAttempted);
        Assert.IsFalse(result.RollbackSucceeded);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Rollback,
            OperationIntentStatus.Failed);
    }

    [TestMethod]
    public async Task CommittedTransactionIsIdempotentlyRecommittedAndVerified()
    {
        var fixture = CreateFixture();
        fixture.AddArtifactAndAggregateCleanup();
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "committed",
            active: true,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Succeeded, result.Status);
        CollectionAssert.AreEqual(
            new[]
            {
                RemoteHelperVerbV1.Status,
                RemoteHelperVerbV1.Verify,
                RemoteHelperVerbV1.Commit,
            },
            fixture.Session.HelperVerbs);
        Assert.IsTrue(
            fixture.Session.HelperVerbs.Contains(RemoteHelperVerbV1.Commit));
        Assert.IsFalse(
            fixture.Session.HelperVerbs.Contains(RemoteHelperVerbV1.Rollback));
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Commit,
            OperationIntentStatus.Reconciled);
    }

    [TestMethod]
    public async Task CommittedTransactionWithoutArtifactRemainsBlocked()
    {
        var fixture = CreateFixture();
        fixture.AddAggregateCleanup();
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "committed",
            active: true,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Blocked, result.Status);
        Assert.AreEqual(
            "recovery.committed_artifact_missing",
            result.FailureCode);
        CollectionAssert.AreEqual(
            new[] { RemoteHelperVerbV1.Status },
            fixture.Session.HelperVerbs);
    }

    [TestMethod]
    public async Task CommittedRemoteVerifyFailureRemainsBlockedWithoutRollback()
    {
        var fixture = CreateFixture();
        fixture.AddArtifactAndAggregateCleanup();
        fixture.Session.FailingVerbs.Add(RemoteHelperVerbV1.Verify);
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "committed",
            active: true,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Blocked, result.Status);
        Assert.AreEqual(
            "recovery.committed_remote_verify_failed",
            result.FailureCode);
        Assert.IsFalse(result.RollbackAttempted);
        CollectionAssert.DoesNotContain(
            fixture.Session.HelperVerbs,
            RemoteHelperVerbV1.Rollback);
    }

    [TestMethod]
    public async Task CommittedTlsVerifierExceptionRemainsBlockedWithoutRollback()
    {
        var fixture = CreateFixture();
        fixture.AddArtifactAndAggregateCleanup();
        fixture.TlsVerifier.Exception =
            new IOException("Synthetic TLS verifier failure.");
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "committed",
            active: true,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Blocked, result.Status);
        Assert.AreEqual(
            "recovery.committed_tls_verify_failed",
            result.FailureCode);
        Assert.IsFalse(result.RollbackAttempted);
    }

    [TestMethod]
    public async Task SuccessfulRollbackWithFailedAbortRemainsBlocked()
    {
        var fixture = CreateFixture();
        fixture.AddArtifactAndAggregateCleanup();
        fixture.TlsVerifier.Success = false;
        fixture.Session.FailingVerbs.Add(RemoteHelperVerbV1.Abort);
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "active",
            active: true,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Blocked, result.Status);
        Assert.AreEqual("recovery.abort_required", result.FailureCode);
        Assert.IsTrue(result.RollbackSucceeded);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Rollback,
            OperationIntentStatus.Reconciled);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Abort,
            OperationIntentStatus.Failed);
    }

    [TestMethod]
    public async Task RolledBackStatusIsAbortedBeforeTerminalFailure()
    {
        var fixture = CreateFixture();
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "rolled-back",
            active: false,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        CollectionAssert.AreEqual(
            new[] { RemoteHelperVerbV1.Status, RemoteHelperVerbV1.Abort },
            fixture.Session.HelperVerbs);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Abort,
            OperationIntentStatus.Reconciled);
    }

    [TestMethod]
    public async Task RollingBackStatusCompletesRollbackThenAborts()
    {
        var fixture = CreateFixture();
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "rolling-back",
            active: false,
            recoveryRequired: true);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        CollectionAssert.AreEqual(
            new[]
            {
                RemoteHelperVerbV1.Status,
                RemoteHelperVerbV1.Rollback,
                RemoteHelperVerbV1.Abort,
            },
            fixture.Session.HelperVerbs);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Rollback,
            OperationIntentStatus.Reconciled);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Abort,
            OperationIntentStatus.Reconciled);
    }

    [TestMethod]
    public async Task PersistedChallengeOutsideEnrollmentRootIsNeverRemoved()
    {
        var fixture = CreateFixture();
        _ = fixture.AddChallengeWrite(
            OperationIntentStatus.Planned,
            RemotePosixPath.Parse("/tmp/not-enrolled/token"));
        fixture.Session.StatusResult = new RemoteHelperResult(
            1,
            null,
            string.Empty,
            "{\"code\":\"helper.state_missing\"}");

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Blocked, result.Status);
        Assert.AreEqual(
            "recovery.challenge_cleanup_required",
            result.FailureCode);
        Assert.IsEmpty(fixture.Session.RemovedPaths);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.ChallengeWrite,
            OperationIntentStatus.Planned);
    }

    [TestMethod]
    public async Task MultiSanRecoveryTlsVerificationIsBoundedAndParallel()
    {
        var dnsNames = Enumerable.Range(0, 20)
            .Select(index => $"recovery-{index}.example.test")
            .ToArray();
        var fixture = CreateFixture(dnsNames);
        fixture.AddArtifactAndAggregateCleanup();
        fixture.TlsVerifier.Delay = TimeSpan.FromMilliseconds(25);
        fixture.Session.StatusOutput = CreateStatusJson(
            fixture.OperationId,
            "active",
            active: true,
            recoveryRequired: false);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Succeeded, result.Status);
        Assert.AreEqual(dnsNames.Length, fixture.TlsVerifier.Requests.Count);
        Assert.IsGreaterThan(1, fixture.TlsVerifier.MaximumConcurrency);
        Assert.IsLessThanOrEqualTo(8, fixture.TlsVerifier.MaximumConcurrency);
    }

    [TestMethod]
    public async Task MultiChallengeRecoveryCleanupIsBoundedAndReconcilesEveryPath()
    {
        var fixture = CreateFixture();
        var paths = Enumerable.Range(0, 20)
            .Select(
                index => fixture.AddChallengeWrite(
                    OperationIntentStatus.Planned,
                    fixture.Request.ChallengeWebroot.Combine(
                        new RemoteTokenSegment($"restart-token-{index}"))))
            .ToArray();
        fixture.Session.RemovalDelay = TimeSpan.FromMilliseconds(25);
        fixture.Session.StatusResult = new RemoteHelperResult(
            1,
            null,
            string.Empty,
            "{\"code\":\"helper.state_missing\"}");

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        Assert.IsTrue(result.ChallengeCleanupVerified);
        Assert.AreEqual(paths.Length, fixture.Session.RemovedPaths.Count);
        Assert.IsGreaterThan(1, fixture.Session.MaximumRemovalConcurrency);
        Assert.IsLessThanOrEqualTo(8, fixture.Session.MaximumRemovalConcurrency);
        Assert.IsTrue(
            fixture.Store.ReadOperationIntents(fixture.OperationId).All(
                static intent =>
                    intent.Kind != OperationIntentKind.ChallengeWrite ||
                    intent.Status == OperationIntentStatus.Reconciled));
    }

    [TestMethod]
    public async Task MalformedStatusJsonFailsClosed()
    {
        var fixture = CreateFixture();
        fixture.Session.StatusOutput = "{not-json";

        await Assert.ThrowsExactlyAsync<InvalidDataException>(
            fixture.RecoverAsync);

        CollectionAssert.AreEqual(
            new[] { RemoteHelperVerbV1.Status },
            fixture.Session.HelperVerbs);
    }

    [TestMethod]
    public async Task MismatchedStatusTransactionFailsClosed()
    {
        var fixture = CreateFixture();
        fixture.Session.StatusOutput = CreateStatusJson(
            new OperationId(Guid.Parse("8e3091dd-f838-496e-a2a9-2ade8c0d9bb8")),
            "active",
            active: true,
            recoveryRequired: false);

        await Assert.ThrowsExactlyAsync<InvalidDataException>(
            fixture.RecoverAsync);

        CollectionAssert.AreEqual(
            new[] { RemoteHelperVerbV1.Status },
            fixture.Session.HelperVerbs);
    }

    [TestMethod]
    public async Task MissingStateBeforeActivationFailsWithoutActivationOrRollback()
    {
        var fixture = CreateFixture();
        fixture.Session.StatusResult = new RemoteHelperResult(
            1,
            null,
            string.Empty,
            "{\"code\":\"helper.state_missing\"}");

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        Assert.AreEqual("recovery.transaction_missing", result.FailureCode);
        Assert.IsFalse(result.ActivationAttempted);
        Assert.IsFalse(result.RollbackAttempted);
        CollectionAssert.AreEqual(
            new[] { RemoteHelperVerbV1.Status },
            fixture.Session.HelperVerbs);
    }

    [TestMethod]
    public async Task StatusAccessFailureAfterActivationRequiresManualRollback()
    {
        var fixture = CreateFixture();
        _ = fixture.Store.CreateOrGetOperationIntent(
            new OperationIntent(
                OperationIntentId.Create(),
                fixture.OperationId,
                sequence: 1,
                OperationIntentKind.Activate,
                "recovery-fixture-activation",
                OperationIntentStatus.Applied,
                testTime.AddSeconds(1),
                testTime.AddSeconds(2)));
        fixture.Session.StatusResult = new RemoteHelperResult(
            null,
            "connection-lost",
            string.Empty,
            string.Empty);

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(LiveRenewalStatus.RollbackRequired, result.Status);
        Assert.AreEqual("recovery.status_failed", result.FailureCode);
        Assert.IsTrue(result.ActivationAttempted);
        Assert.IsFalse(result.RollbackAttempted);
        CollectionAssert.AreEqual(
            new[] { RemoteHelperVerbV1.Status },
            fixture.Session.HelperVerbs);
        AssertIntent(
            fixture.Store,
            fixture.OperationId,
            OperationIntentKind.Activate,
            OperationIntentStatus.Applied);
    }

    private RecoveryFixture CreateFixture(
        IEnumerable<string>? dnsNames = null,
        TimeSpan? recoveryPhaseTimeout = null)
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "CertBaton.UnitTests",
            Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(directory);
        testDirectories.Add(directory);
        return new RecoveryFixture(
            Path.Combine(directory, "state.db"),
            dnsNames,
            recoveryPhaseTimeout);
    }

    private static void AssertIntent(
        SqliteProductionStore store,
        OperationId operationId,
        OperationIntentKind expectedKind,
        OperationIntentStatus expectedStatus)
    {
        var matches = store
            .ReadOperationIntents(operationId)
            .Where(item => item.Kind == expectedKind)
            .ToArray();
        Assert.HasCount(1, matches);
        Assert.AreEqual(expectedStatus, matches[0].Status);
        if (expectedStatus is
            OperationIntentStatus.Applied or OperationIntentStatus.Reconciled)
        {
            Assert.IsNotNull(matches[0].AppliedAtUtc);
        }
    }

    private static string CreateStatusJson(
        OperationId operationId,
        string status,
        bool active,
        bool recoveryRequired) =>
        JsonSerializer.Serialize(
            new
            {
                version = 1,
                success = true,
                code = "helper.status",
                transactionId = operationId.ToString(),
                status,
                active,
                recoveryRequired,
            });

    private sealed class RecoveryFixture
    {
        private static readonly SecretReference sshSecretReference =
            new(Guid.Parse("95c8f265-e040-4511-bd65-a6d67c026fbd"));
        private static readonly SecretReference accountSecretReference =
            new(Guid.Parse("be5c5ef5-38a4-4efe-bf69-aa5d6cbd76f3"));
        private static readonly SecretReference certificateSecretReference =
            new(Guid.Parse("5c44511a-b916-40ba-ac0b-c8cc91818e30"));

        private long nextIntentSequence;

        public RecoveryFixture(
            string databasePath,
            IEnumerable<string>? dnsNames,
            TimeSpan? recoveryPhaseTimeout)
        {
            Store = new SqliteProductionStore(databasePath);
            Store.Initialize(testTime);
            var rawHostKey = Encoding.UTF8.GetBytes(
                "production-recovery-test-host-key");
            var fingerprint =
                "SHA256:" +
                Convert.ToBase64String(SHA256.HashData(rawHostKey)).TrimEnd('=');
            var connectionId = new ConnectionId(
                Guid.Parse("b59233c4-25d7-49b2-b2eb-4499fc3c218d"));
            Store.SaveConnection(
                new ConnectionProfile(
                    connectionId,
                    "Recovery test SSH",
                    new ConnectionEndpoint("ssh.recovery.example.test"),
                    "deploy",
                    sshSecretReference.ToString(),
                    "ssh-ed25519",
                    fingerprint,
                    testTime,
                    testTime,
                    enabled: true,
                    rawHostKey));
            var targetId = new TargetId(
                Guid.Parse("b6d134ec-15c2-4eed-a93a-765db24231d0"));
            Store.SaveTarget(
                new CertificateTarget(
                    targetId,
                    connectionId,
                    "Recovery test target",
                    new TargetDnsName("recovery.example.test"),
                    [],
                    TargetLifecycleStatus.Ready,
                    testTime,
                    testTime));
            OperationId = new OperationId(
                Guid.Parse("e0c9c263-f54e-4e3b-aa0d-653fffe0b674"));
            _ = Store.CreateOrGetOperation(
                RenewalOperation.CreateQueued(
                    OperationId,
                    targetId,
                    "production-recovery-test",
                    testTime));
            ExecutionEpoch = Guid.Parse(
                "3ee6c576-cbdd-471c-8e87-c2945292cc25");
            Assert.IsNotNull(
                Store.TryStartOperation(
                    OperationId,
                    ExecutionEpoch,
                    testTime.AddSeconds(1)));

            var endpoint = RemoteSshEndpoint.Create(
                "ssh.recovery.example.test",
                22,
                "deploy");
            var pin = SshHostKeyPin.Create(
                endpoint.Host,
                endpoint.Port,
                "ssh-ed25519",
                fingerprint,
                rawHostKey);
            Request = new LiveHttp01RenewalRequest(
                OperationId.Value,
                dnsNames?.ToArray() ?? ["recovery.example.test"],
                new Uri("https://acme.example.test/directory"),
                ["mailto:operator@example.test"],
                termsOfServiceAgreed: true,
                AcmeCertificateTrustMode.UntrustedTest,
                accountSecretReference,
                new RemoteSshConnectionOptions(endpoint, pin),
                sshSecretReference,
                RemotePosixPath.Parse("/var/www/challenges"),
                RemotePosixPath.Parse("/var/lib/certbaton/incoming"));
            Session = new FakeRemoteSession(endpoint);
            TlsVerifier = new FakeTlsVerifier();
            Executor = new ProductionLiveRenewalExecutor(
                Store,
                new UnusedAcmeEngine(),
                new UnusedAccountStore(),
                new UnusedCertificateKeyStore(),
                new UnusedIssuedCertificateStore(),
                new FakeRemoteSessionFactory(Session),
                new FakeSecretVault(sshSecretReference),
                new UnusedHttpVerifier(),
                TlsVerifier,
                new UnusedCertificateInspector(),
                new FixedTimeProvider(testTime.AddMinutes(1)),
                recoveryPhaseTimeout);
        }

        public SqliteProductionStore Store { get; }

        public OperationId OperationId { get; }

        public Guid ExecutionEpoch { get; }

        public LiveHttp01RenewalRequest Request { get; }

        public FakeRemoteSession Session { get; }

        public FakeTlsVerifier TlsVerifier { get; }

        public ProductionLiveRenewalExecutor Executor { get; }

        public Task<LiveRenewalResult> RecoverAsync() =>
            Executor.RecoverAsync(
                OperationId,
                ExecutionEpoch,
                Request,
                CancellationToken.None);

        public RemotePosixPath AddChallengeWrite(
            OperationIntentStatus status,
            RemotePosixPath? remotePath = null)
        {
            var sequence = Interlocked.Increment(ref nextIntentSequence);
            var path = remotePath ?? Request.ChallengeWebroot.Combine(
                new RemoteTokenSegment($"restart-token-{sequence}"));
            _ = Store.CreateOrGetOperationIntent(
                new OperationIntent(
                    OperationIntentId.Create(),
                    OperationId,
                    sequence,
                    OperationIntentKind.ChallengeWrite,
                    $"recovery-fixture-challenge-{sequence}",
                    status,
                    testTime.AddSeconds(1),
                    appliedAtUtc:
                        status is OperationIntentStatus.Applied or
                            OperationIntentStatus.Reconciled
                            ? testTime.AddSeconds(2)
                            : null,
                    remotePath: path.Value));
            return path;
        }

        public void AddArtifactAndAggregateCleanup()
        {
            _ = Store.CreateOrGetCertificateArtifact(
                new CertificateArtifact(
                    CertificateArtifactId.Create(),
                    OperationId,
                    new Sha256Digest(new string('A', 64)),
                    new Sha256Digest(new string('B', 64)),
                    certificateSecretReference.ToString(),
                    testTime.AddHours(-1),
                    testTime.AddDays(89),
                    CertificateArtifactStatus.Issued,
                    testTime));
            AddAggregateCleanup();
        }

        public void AddAggregateCleanup()
        {
            _ = Store.AppendOperationEvidence(
                OperationId,
                OperationEvidenceKind.Cleanup,
                stage: null,
                OperationEvidenceOutcome.Succeeded,
                testTime.AddSeconds(2),
                "challenge.cleanup_complete",
                "All owned HTTP-01 challenge artifacts were removed.");
        }
    }

    private sealed class FakeRemoteSessionFactory(FakeRemoteSession session) :
        IRemoteSshSessionFactory
    {
        public ValueTask<IRemoteSshSession> ConnectAsync(
            RemoteSshConnectionOptions options,
            RemotePrivateKeyMaterial privateKey,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.AreEqual(session.Endpoint, options.Endpoint);
            Assert.IsGreaterThan(0, privateKey.Length);
            return ValueTask.FromResult<IRemoteSshSession>(session);
        }
    }

    private sealed class FakeRemoteSession(RemoteSshEndpoint endpoint) :
        IRemoteSshSession
    {
        private readonly object sync = new();
        private int currentRemovalConcurrency;
        private int maximumRemovalConcurrency;

        public RemoteSshEndpoint Endpoint { get; } = endpoint;

        public string StatusOutput { get; set; } = string.Empty;

        public RemoteHelperResult? StatusResult { get; set; }

        public HashSet<RemoteHelperVerbV1> FailingVerbs { get; } = [];

        public List<RemoteHelperVerbV1> HelperVerbs { get; } = [];

        public List<RemotePosixPath> RemovedPaths { get; } = [];

        public bool FailRemoval { get; set; }

        public TimeSpan RemovalDelay { get; set; }

        public int MaximumRemovalConcurrency =>
            Volatile.Read(ref maximumRemovalConcurrency);

        public Task<RemoteHelperResult> InvokeHelperAsync(
            RemoteHelperVerbV1 verb,
            RemoteTransactionId transactionId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            HelperVerbs.Add(verb);
            if (verb == RemoteHelperVerbV1.Status)
            {
                return Task.FromResult(
                    StatusResult ??
                    new RemoteHelperResult(
                        0,
                        null,
                        StatusOutput,
                        string.Empty));
            }

            return Task.FromResult(
                FailingVerbs.Contains(verb)
                    ? new RemoteHelperResult(
                        1,
                        null,
                        string.Empty,
                        "helper failed")
                    : new RemoteHelperResult(
                        0,
                        null,
                        "{}",
                        string.Empty));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        public Task<bool> FileExistsAsync(
            RemotePosixPath path,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task UploadFileAsync(
            RemotePosixPath path,
            Stream content,
            RemoteWriteMode writeMode,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<byte[]> ReadFileAsync(
            RemotePosixPath path,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<RemoteFileSha256> ComputeSha256Async(
            RemotePosixPath path,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public async Task RemoveFileAsync(
            RemotePosixPath path,
            MissingFileBehavior missingFileBehavior,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var concurrency = Interlocked.Increment(
                ref currentRemovalConcurrency);
            UpdateMaximum(ref maximumRemovalConcurrency, concurrency);
            try
            {
                if (RemovalDelay > TimeSpan.Zero)
                {
                    await Task.Delay(RemovalDelay, cancellationToken);
                }

                if (FailRemoval)
                {
                    throw new IOException("Synthetic removal failure.");
                }

                lock (sync)
                {
                    RemovedPaths.Add(path);
                }
            }
            finally
            {
                _ = Interlocked.Decrement(ref currentRemovalConcurrency);
            }
        }

        private static void UpdateMaximum(ref int location, int candidate)
        {
            var observed = Volatile.Read(ref location);
            while (candidate > observed)
            {
                var prior = Interlocked.CompareExchange(
                    ref location,
                    candidate,
                    observed);
                if (prior == observed)
                {
                    return;
                }

                observed = prior;
            }
        }
    }

    private sealed class FakeSecretVault(SecretReference reference) : ISecretVault
    {
        public bool Contains(SecretReference candidate) => candidate == reference;

        public byte[] Read(SecretReference candidate) =>
            candidate == reference
                ? Encoding.UTF8.GetBytes("synthetic-private-key")
                : throw new KeyNotFoundException();

        public void Store(
            SecretReference candidate,
            ReadOnlySpan<byte> secret,
            bool replace = false) =>
            throw new NotSupportedException();

        public void ImportProtected(
            SecretReference candidate,
            ReadOnlySpan<byte> protectedSecret,
            bool replace = false) =>
            throw new NotSupportedException();

        public bool Delete(SecretReference candidate) =>
            throw new NotSupportedException();
    }

    private sealed class FakeTlsVerifier : IPublicTlsVerifier
    {
        private readonly object sync = new();
        private int currentConcurrency;
        private int maximumConcurrency;

        public bool Success { get; set; } = true;

        public TimeSpan Delay { get; set; }

        public Exception? Exception { get; set; }

        public List<PublicTlsVerificationRequest> Requests { get; } = [];

        public int MaximumConcurrency => Volatile.Read(ref maximumConcurrency);

        public async Task<PublicTlsVerificationResult> VerifyAsync(
            PublicTlsVerificationRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var concurrency = Interlocked.Increment(ref currentConcurrency);
            UpdateMaximum(ref maximumConcurrency, concurrency);
            lock (sync)
            {
                Requests.Add(request);
            }

            try
            {
                if (Delay > TimeSpan.Zero)
                {
                    await Task.Delay(Delay, cancellationToken);
                }

                if (Exception is not null)
                {
                    throw Exception;
                }

                return new PublicTlsVerificationResult(
                    Success,
                    Success ? "tls.verified" : "tls.leaf_mismatch",
                    request.ExpectedLeafSha256,
                    testTime.AddHours(-1),
                    testTime.AddDays(89),
                    HostnameMatched: Success,
                    ChainTrusted: false,
                    [IPAddress.Parse("192.0.2.20")]);
            }
            finally
            {
                _ = Interlocked.Decrement(ref currentConcurrency);
            }
        }

        private static void UpdateMaximum(ref int location, int candidate)
        {
            var observed = Volatile.Read(ref location);
            while (candidate > observed)
            {
                var prior = Interlocked.CompareExchange(
                    ref location,
                    candidate,
                    observed);
                if (prior == observed)
                {
                    return;
                }

                observed = prior;
            }
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class UnusedAcmeEngine : IAcmeEngine
    {
        public Task<AcmeAccountResult> EnsureAccountAsync(
            AcmeAccountRequest request,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AcmeOrder> CreateOrderAsync(
            AcmeAccount account,
            AcmeOrderRequest request,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AcmeOrder> GetOrderAsync(
            AcmeAccount account,
            Uri orderUri,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<IReadOnlyList<AcmeHttp01Challenge>> GetHttp01ChallengesAsync(
            AcmeAccount account,
            Uri orderUri,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AcmeChallenge> AnswerHttp01ChallengeAsync(
            AcmeAccount account,
            AcmeHttp01Challenge challenge,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AcmeChallengePollResult> PollHttp01ChallengeAsync(
            AcmeAccount account,
            AcmeHttp01Challenge challenge,
            AcmePollingPolicy? policy = null,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AcmeOrder> FinalizeOrderAsync(
            AcmeAccount account,
            Uri orderUri,
            ReadOnlyMemory<byte> certificateSigningRequestDer,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AcmeOrderPollResult> PollOrderAsync(
            AcmeAccount account,
            Uri orderUri,
            AcmePollingPolicy? policy = null,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AcmeCertificateChain> DownloadCertificateAsync(
            AcmeAccount account,
            Uri orderUri,
            string? preferredChain = null,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class UnusedAccountStore : IAcmeAccountStore
    {
        public Task<AcmeAccount?> LoadAsync(
            Uri directoryUri,
            SecretReference accountKeyReference,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task SaveAsync(
            AcmeAccount account,
            SecretReference accountKeyReference,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class UnusedCertificateKeyStore : ICertificatePrivateKeyStore
    {
        public Task<SecretReference> StorePendingAsync(
            Guid operationId,
            ReadOnlyMemory<byte> privateKeyPem,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class UnusedIssuedCertificateStore : IIssuedCertificateStore
    {
        public Task PersistIssuedAsync(
            LiveIssuedCertificateArtifact certificateArtifact,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class UnusedHttpVerifier : IPublicHttp01Verifier
    {
        public Task<Http01VerificationResult> VerifyAsync(
            Http01VerificationRequest request,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class UnusedCertificateInspector :
        ICertificateMaterialInspector
    {
        public CertificateInspectionResult Inspect(
            string certificateChainPem,
            string privateKeyPem,
            string expectedHostname,
            DateTimeOffset nowUtc) =>
            throw new NotSupportedException();
    }
}
