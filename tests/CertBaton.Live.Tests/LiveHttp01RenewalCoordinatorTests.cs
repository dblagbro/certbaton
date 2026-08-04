using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CertBaton.Application.Acme;
using CertBaton.Application.Live;
using CertBaton.Application.Remote;
using CertBaton.Application.Security;
using CertBaton.Application.Verification;

namespace CertBaton.Live.Tests;

[TestClass]
public sealed class LiveHttp01RenewalCoordinatorTests
{
    [TestMethod]
    public async Task HappyPathUsesWriteAheadIntentsAndRequiresCleanupAndPublicTls()
    {
        var fixture = new WorkflowFixture(
            AcmeCertificateTrustMode.UntrustedTest);
        Assert.IsTrue(
            fixture.Vault.Contains(
                fixture.Request.SshPrivateKeyReference));

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(
            LiveRenewalStatus.Succeeded,
            result.Status,
            $"Failure: {result.FailureCode}; trace: {string.Join(",", fixture.Trace)}");
        Assert.IsTrue(result.ChallengeCleanupVerified);
        Assert.IsTrue(result.PublicTlsVerified);
        Assert.IsTrue(result.ActivationAttempted);
        Assert.IsNull(result.FailureCode);
        Assert.AreEqual(TlsTrustPolicy.ExpectedLeaf, result.TlsTrustPolicy);
        Assert.AreEqual(
            TlsTrustPolicy.ExpectedLeaf,
            fixture.TlsVerifier.LastRequest?.TrustPolicy);
        CollectionAssert.AreEquivalent(
            fixture.Request.DnsNames.ToArray(),
            fixture.TlsVerifier.Requests
                .Select(static request => request.Hostname)
                .ToArray());
        Assert.IsTrue(fixture.Acme.CsrValidated);
        Assert.IsTrue(fixture.KeyStore.KeyValidated);
        Assert.IsNotNull(fixture.ArtifactStore.LastArtifact);
        Assert.AreEqual(
            result.PublicKeySha256,
            fixture.ArtifactStore.LastArtifact.PublicKeySha256);
        Assert.IsNotNull(result.NotBeforeUtc);
        Assert.IsNotNull(result.NotAfterUtc);
        Assert.AreEqual(2, fixture.Remote.RemovedPaths.Count);
        Assert.AreEqual(
            3,
            fixture.Journal.Entries.Count(
                static entry =>
                    entry.Action ==
                    LiveRenewalJournalAction.ChallengeCleanup &&
                    entry.Outcome ==
                    LiveRenewalJournalOutcome.Succeeded));
        Assert.HasCount(
            1,
            fixture.Journal.Entries.Where(
                static entry =>
                    entry.Code == "challenge.cleanup_complete"));
        Assert.HasCount(
            1,
            fixture.Journal.Entries.Where(
                static entry => entry.Code == "tls.all_names_verified"));
        CollectionAssert.Contains(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Commit);
        CollectionAssert.DoesNotContain(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Rollback);
        AssertTraceOrder(
            fixture.Trace,
            "journal:ChallengeWrite:Planned",
            "upload:/var/www/challenges/token-0");
        Assert.AreEqual(
            "/var/www/challenges/token-0",
            fixture.Journal.Entries.Single(
                static entry =>
                    entry.Action == LiveRenewalJournalAction.ChallengeWrite &&
                    entry.Outcome == LiveRenewalJournalOutcome.Planned &&
                    entry.Subject == "/var/www/challenges/token-0").Subject);
        AssertTraceOrder(
            fixture.Trace,
            "journal:CertificateKeyPersistence:Applied",
            "acme:finalize");
        AssertTraceOrder(
            fixture.Trace,
            "artifact:store",
            "helper:Prepare");
        AssertTraceOrder(
            fixture.Trace,
            "journal:CertificateDeployment:Planned",
            $"upload:/srv/certbaton/incoming/{fixture.Request.OperationId:D}/fullchain.pem");
        AssertTraceOrder(
            fixture.Trace,
            "journal:Activation:Planned",
            "helper:Activate");
        Assert.IsNotNull(fixture.Vault.LastReadBuffer);
        Assert.IsTrue(
            fixture.Vault.LastReadBuffer.All(
                static value => value == 0),
            "The mutable SSH secret returned by the vault must be zeroed.");
    }

    [TestMethod]
    public async Task ChallengeMismatchIsNeverAcknowledgedAndIsCleaned()
    {
        var fixture = new WorkflowFixture();
        fixture.HttpVerifier.Success = false;
        fixture.HttpVerifier.Code = "http01.content_mismatch";

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        Assert.AreEqual("http01.content_mismatch", result.FailureCode);
        Assert.IsTrue(result.ChallengeCleanupVerified);
        Assert.AreEqual(0, fixture.Acme.AnswerCalls);
        Assert.AreEqual(1, fixture.Remote.RemovedPaths.Count);
        CollectionAssert.DoesNotContain(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Activate);
    }

    [TestMethod]
    public async Task AcmeFailureStillRemovesEveryPublishedChallenge()
    {
        var fixture = new WorkflowFixture();
        fixture.Acme.ThrowWhenAnswering = true;

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        Assert.AreEqual(
            "challenge.acknowledgement_failed",
            result.FailureCode);
        Assert.IsTrue(result.ChallengeCleanupVerified);
        Assert.AreEqual(1, fixture.Remote.RemovedPaths.Count);
        Assert.IsTrue(
            fixture.Journal.Entries.Any(
                static entry =>
                    entry.Action ==
                    LiveRenewalJournalAction.ChallengeCleanup &&
                    entry.Outcome ==
                    LiveRenewalJournalOutcome.Succeeded));
    }

    [TestMethod]
    public async Task CleanupWithoutDurableEvidenceCanNeverSucceed()
    {
        var fixture = new WorkflowFixture();
        fixture.Remote.FailChallengeRemoval = true;

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Blocked, result.Status);
        Assert.AreEqual(
            "recovery.challenge_cleanup_required",
            result.FailureCode);
        Assert.IsFalse(result.ChallengeCleanupVerified);
        Assert.IsFalse(fixture.Acme.FinalizeCalled);
    }

    [TestMethod]
    public async Task PublicTlsFailureRollsBackBeforeReturningFailure()
    {
        var fixture = new WorkflowFixture();
        fixture.TlsVerifier.Success = false;
        fixture.TlsVerifier.Code = "tls.mismatch";

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        Assert.AreEqual("tls.mismatch", result.FailureCode);
        Assert.IsTrue(result.RollbackAttempted);
        Assert.IsTrue(result.RollbackSucceeded);
        Assert.IsFalse(result.PublicTlsVerified);
        CollectionAssert.Contains(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Rollback);
        CollectionAssert.Contains(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Abort);
        CollectionAssert.DoesNotContain(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Commit);
        AssertTraceOrder(
            fixture.Trace,
            "helper:Activate",
            "helper:Rollback");
        AssertTraceOrder(
            fixture.Trace,
            "helper:Rollback",
            "helper:Abort");
    }

    [TestMethod]
    public async Task FailedAbortAfterSuccessfulRollbackKeepsRenewalBlocked()
    {
        var fixture = new WorkflowFixture();
        fixture.TlsVerifier.Success = false;
        fixture.Remote.AfterHelper = verb =>
        {
            if (verb == RemoteHelperVerbV1.Rollback)
            {
                fixture.Remote.FailingVerb = RemoteHelperVerbV1.Abort;
            }
        };

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Blocked, result.Status);
        Assert.AreEqual("recovery.abort_required", result.FailureCode);
        Assert.IsTrue(result.RollbackSucceeded);
        CollectionAssert.Contains(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Abort);
    }

    [TestMethod]
    public async Task FailedRollbackReturnsRollbackRequired()
    {
        var fixture = new WorkflowFixture();
        fixture.TlsVerifier.Success = false;
        fixture.Remote.FailingVerb = RemoteHelperVerbV1.Rollback;

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(
            LiveRenewalStatus.RollbackRequired,
            result.Status);
        Assert.IsTrue(result.RollbackAttempted);
        Assert.IsFalse(result.RollbackSucceeded);
        Assert.IsTrue(
            fixture.Journal.Entries.Any(
                static entry =>
                    entry.Action == LiveRenewalJournalAction.Rollback &&
                    entry.Outcome == LiveRenewalJournalOutcome.Failed));
    }

    [TestMethod]
    public async Task CancellationBeforeActivationAbortsWithoutActivating()
    {
        using var cancellation = new CancellationTokenSource();
        var fixture = new WorkflowFixture();
        fixture.Remote.AfterHelper = verb =>
        {
            if (verb == RemoteHelperVerbV1.Validate)
            {
                cancellation.Cancel();
            }
        };

        var result = await fixture.Coordinator.RunAsync(
            fixture.Request,
            cancellation.Token);

        Assert.AreEqual(LiveRenewalStatus.Cancelled, result.Status);
        Assert.AreEqual("operation.cancelled", result.FailureCode);
        Assert.IsFalse(result.ActivationAttempted);
        CollectionAssert.DoesNotContain(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Activate);
        CollectionAssert.Contains(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Abort);
    }

    [TestMethod]
    public async Task CancellationAfterActivationBoundaryCannotInterruptRecoveryCriticalWork()
    {
        using var cancellation = new CancellationTokenSource();
        var fixture = new WorkflowFixture();
        fixture.Remote.AfterHelper = verb =>
        {
            if (verb == RemoteHelperVerbV1.Activate)
            {
                cancellation.Cancel();
            }
        };

        var result = await fixture.Coordinator.RunAsync(
            fixture.Request,
            cancellation.Token);

        Assert.IsTrue(cancellation.IsCancellationRequested);
        Assert.AreEqual(LiveRenewalStatus.Succeeded, result.Status);
        CollectionAssert.Contains(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Verify);
        CollectionAssert.Contains(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Commit);
    }

    [TestMethod]
    public async Task DurableExistingAccountIsReusedAndResaved()
    {
        var fixture = new WorkflowFixture();
        fixture.AccountStore.LoadResult = new AcmeAccount(
            fixture.Request.AcmeDirectoryUri,
            new Uri("https://acme.test/account/existing"),
            "existing-account-key"u8);

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Succeeded, result.Status);
        Assert.IsTrue(fixture.Acme.ExistingAccountObserved);
        Assert.AreEqual(1, fixture.AccountStore.SaveCalls);
    }

    [TestMethod]
    public void RequestRejectsWildcardBeforeAnyDependencyCanRun()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = WorkflowFixture.CreateRequest(["*.example.test"]));
    }

    [TestMethod]
    public async Task DependencyExceptionDetailsAreNotReturnedOrJournaled()
    {
        var fixture = new WorkflowFixture();
        fixture.Remote.UploadException = new InvalidOperationException(
            "PRIVATE-KEY-SHOULD-NEVER-ESCAPE");

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual("challenge.upload_failed", result.FailureCode);
        Assert.IsFalse(
            fixture.Journal.Entries.Any(
                static entry =>
                    entry.Code.Contains(
                        "PRIVATE-KEY",
                        StringComparison.Ordinal) ||
                    entry.Description.Contains(
                        "PRIVATE-KEY",
                        StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task PrepareUploadPathMismatchAbortsBeforeCertificateUpload()
    {
        var fixture = new WorkflowFixture();
        fixture.Remote.PrepareOutput = JsonSerializer.Serialize(
            new
            {
                version = 1,
                success = true,
                code = "helper.prepared",
                transactionId = fixture.Request.OperationId.ToString("D"),
                uploadPath = "/srv/certbaton/incoming/not-this-operation",
            });

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Failed, result.Status);
        Assert.AreEqual("remote.prepare_path_mismatch", result.FailureCode);
        CollectionAssert.Contains(
            fixture.Remote.HelperVerbs,
            RemoteHelperVerbV1.Abort);
        Assert.IsFalse(
            fixture.Trace.Any(
                static entry =>
                    entry.EndsWith("/fullchain.pem", StringComparison.Ordinal) ||
                    entry.EndsWith("/privkey.pem", StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task FailedPreActivationAbortKeepsRenewalBlocked()
    {
        var fixture = new WorkflowFixture();
        fixture.Remote.PrepareOutput = "{not-json";
        fixture.Remote.FailingVerb = RemoteHelperVerbV1.Abort;

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Blocked, result.Status);
        Assert.AreEqual("recovery.abort_required", result.FailureCode);
        Assert.IsFalse(result.ActivationAttempted);
    }

    [TestMethod]
    public async Task MultiSanTlsVerificationIsBoundedAndParallel()
    {
        var dnsNames = Enumerable.Range(0, 20)
            .Select(index => $"san-{index}.example.test")
            .ToArray();
        var fixture = new WorkflowFixture(dnsNames: dnsNames);
        fixture.TlsVerifier.Delay = TimeSpan.FromMilliseconds(25);

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Succeeded, result.Status);
        Assert.IsGreaterThan(1, fixture.TlsVerifier.MaximumConcurrency);
        Assert.IsLessThanOrEqualTo(8, fixture.TlsVerifier.MaximumConcurrency);
        Assert.AreEqual(dnsNames.Length, fixture.TlsVerifier.Requests.Count);
    }

    [TestMethod]
    public async Task MultiSanChallengeCleanupIsBoundedAndAttemptsEveryFile()
    {
        var dnsNames = Enumerable.Range(0, 20)
            .Select(index => $"cleanup-{index}.example.test")
            .ToArray();
        var fixture = new WorkflowFixture(dnsNames: dnsNames);
        fixture.Remote.ChallengeRemovalDelay = TimeSpan.FromMilliseconds(25);

        var result = await fixture.Coordinator.RunAsync(fixture.Request);

        Assert.AreEqual(LiveRenewalStatus.Succeeded, result.Status);
        Assert.AreEqual(
            dnsNames.Length,
            fixture.Remote.RemovedPaths.Count(
                static path => path.Value.StartsWith(
                    "/var/www/challenges/",
                    StringComparison.Ordinal)));
        Assert.IsGreaterThan(1, fixture.Remote.MaximumRemovalConcurrency);
        Assert.IsLessThanOrEqualTo(8, fixture.Remote.MaximumRemovalConcurrency);
        Assert.AreEqual(
            dnsNames.Length,
            fixture.Journal.Entries.Count(
                static entry =>
                    entry.Action == LiveRenewalJournalAction.ChallengeCleanup &&
                    entry.Outcome == LiveRenewalJournalOutcome.Succeeded &&
                    entry.Code == "challenge.cleaned"));
    }

    private static void AssertTraceOrder(
        IReadOnlyList<string> trace,
        string first,
        string second)
    {
        var firstIndex = trace.IndexOf(first);
        var secondIndex = trace.IndexOf(second);
        Assert.IsTrue(
            firstIndex >= 0,
            $"Trace did not contain '{first}'.");
        Assert.IsTrue(
            secondIndex > firstIndex,
            $"Trace did not place '{second}' after '{first}'.");
    }

    private sealed class WorkflowFixture
    {
        private static readonly byte[] HostKey =
            "fixture-host-key"u8.ToArray();
        private static readonly SecretReference SshSecretReference =
            new(Guid.Parse("dddddddd-dddd-7ddd-8ddd-dddddddddddd"));
        private static readonly SecretReference AccountSecretReference =
            new(Guid.Parse("aaaaaaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa"));

        public WorkflowFixture(
            AcmeCertificateTrustMode trustMode =
                AcmeCertificateTrustMode.PubliclyTrusted,
            IEnumerable<string>? dnsNames = null)
        {
            Trace = [];
            Request = CreateRequest(
                dnsNames ?? ["example.test", "www.example.test"],
                trustMode);
            Vault = new FakeSecretVault(
                SshSecretReference,
                "fixture-ssh-private-key"u8.ToArray());
            Acme = new FakeAcmeEngine(Trace);
            AccountStore = new FakeAccountStore(Trace);
            KeyStore = new FakeCertificateKeyStore(Trace);
            ArtifactStore = new FakeIssuedCertificateStore(Trace);
            Remote = new FakeRemoteSession(
                Request.SshConnection.Endpoint,
                Trace);
            HttpVerifier = new FakeHttp01Verifier();
            TlsVerifier = new FakeTlsVerifier();
            Journal = new FakeJournal(Trace);
            Coordinator = new LiveHttp01RenewalCoordinator(
                Acme,
                AccountStore,
                KeyStore,
                ArtifactStore,
                new FakeRemoteSessionFactory(Remote, Trace),
                Vault,
                HttpVerifier,
                TlsVerifier,
                new FakeCertificateInspector(),
                Journal,
                recoveryTimeout: TimeSpan.FromSeconds(5));
        }

        public List<string> Trace { get; }

        public LiveHttp01RenewalRequest Request { get; }

        public FakeSecretVault Vault { get; }

        public FakeAcmeEngine Acme { get; }

        public FakeAccountStore AccountStore { get; }

        public FakeCertificateKeyStore KeyStore { get; }

        public FakeIssuedCertificateStore ArtifactStore { get; }

        public FakeRemoteSession Remote { get; }

        public FakeHttp01Verifier HttpVerifier { get; }

        public FakeTlsVerifier TlsVerifier { get; }

        public FakeJournal Journal { get; }

        public LiveHttp01RenewalCoordinator Coordinator { get; }

        public static LiveHttp01RenewalRequest CreateRequest(
            IEnumerable<string> dnsNames,
            AcmeCertificateTrustMode trustMode =
                AcmeCertificateTrustMode.PubliclyTrusted)
        {
            var endpoint = RemoteSshEndpoint.Create(
                "fixture.example",
                22,
                "certbaton");
            var fingerprint = "SHA256:" + Convert
                .ToBase64String(SHA256.HashData(HostKey))
                .TrimEnd('=');
            var pin = SshHostKeyPin.Create(
                endpoint.Host,
                endpoint.Port,
                "ssh-ed25519",
                fingerprint,
                HostKey);
            return new LiveHttp01RenewalRequest(
                Guid.Parse("0198ff1a-3aad-7b52-a85b-7e16cfda9e00"),
                dnsNames,
                new Uri("https://acme.test/directory"),
                ["mailto:operator@example.test"],
                termsOfServiceAgreed: true,
                trustMode,
                AccountSecretReference,
                new RemoteSshConnectionOptions(endpoint, pin),
                SshSecretReference,
                RemotePosixPath.Parse("/var/www/challenges"),
                RemotePosixPath.Parse("/srv/certbaton/incoming"));
        }
    }

    private sealed class FakeSecretVault : ISecretVault
    {
        private readonly SecretReference reference;
        private byte[] secret;

        public FakeSecretVault(
            SecretReference expectedReference,
            byte[] initialSecret)
        {
            reference = expectedReference;
            secret = initialSecret;
        }

        public byte[]? LastReadBuffer { get; private set; }

        public bool Contains(SecretReference candidate) =>
            candidate.Value == reference.Value;

        public void Store(
            SecretReference candidate,
            ReadOnlySpan<byte> value,
            bool replace = false)
        {
            _ = replace;
            if (candidate.Value != reference.Value)
            {
                throw new InvalidOperationException();
            }

            secret = value.ToArray();
        }

        public void ImportProtected(
            SecretReference candidate,
            ReadOnlySpan<byte> protectedSecret,
            bool replace = false) =>
            Store(candidate, protectedSecret, replace);

        public byte[] Read(SecretReference candidate)
        {
            if (candidate.Value != reference.Value)
            {
                throw new KeyNotFoundException();
            }

            LastReadBuffer = secret.ToArray();
            return LastReadBuffer;
        }

        public bool Delete(SecretReference candidate) =>
            candidate.Value == reference.Value;
    }

    private sealed class FakeAccountStore(List<string> trace) : IAcmeAccountStore
    {
        private readonly List<string> workflowTrace = trace;

        public AcmeAccount? LoadResult { get; set; }

        public int SaveCalls { get; private set; }

        public Task<AcmeAccount?> LoadAsync(
            Uri directoryUri,
            SecretReference accountKeyReference,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            workflowTrace.Add("account:load");
            return Task.FromResult(LoadResult);
        }

        public Task SaveAsync(
            AcmeAccount account,
            SecretReference accountKeyReference,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SaveCalls++;
            workflowTrace.Add("account:save");
            return Task.CompletedTask;
        }
    }

    private sealed class FakeCertificateKeyStore(List<string> trace) :
        ICertificatePrivateKeyStore
    {
        private readonly List<string> workflowTrace = trace;

        public bool KeyValidated { get; private set; }

        public Task<SecretReference> StorePendingAsync(
            Guid operationId,
            ReadOnlyMemory<byte> privateKeyPem,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            workflowTrace.Add("key:store");
            var privateKeyText = Encoding.ASCII.GetString(
                privateKeyPem.Span);
            using var key = ECDsa.Create();
            key.ImportFromPem(privateKeyText);
            KeyValidated = key.KeySize == 256;
            return Task.FromResult(
                new SecretReference(
                    Guid.Parse(
                        "eeeeeeee-eeee-7eee-8eee-eeeeeeeeeeee")));
        }
    }

    private sealed class FakeJournal(List<string> trace) : ILiveRenewalJournal
    {
        private readonly List<string> workflowTrace = trace;

        public List<LiveRenewalJournalEntry> Entries { get; } = [];

        public Task AppendAsync(
            LiveRenewalJournalEntry entry,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Entries.Add(entry);
            workflowTrace.Add($"journal:{entry.Action}:{entry.Outcome}");
            return Task.CompletedTask;
        }
    }

    private sealed class FakeIssuedCertificateStore(List<string> trace) :
        IIssuedCertificateStore
    {
        private readonly List<string> workflowTrace = trace;

        public LiveIssuedCertificateArtifact? LastArtifact { get; private set; }

        public Task PersistIssuedAsync(
            LiveIssuedCertificateArtifact certificateArtifact,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastArtifact = certificateArtifact;
            workflowTrace.Add("artifact:store");
            return Task.CompletedTask;
        }
    }

    private sealed class FakeAcmeEngine(List<string> trace) : IAcmeEngine
    {
        private readonly List<string> workflowTrace = trace;
        private IReadOnlyList<string> dnsNames = [];
        private string? certificatePem;

        public bool ThrowWhenAnswering { get; set; }

        public bool ExistingAccountObserved { get; private set; }

        public int AnswerCalls { get; private set; }

        public bool CsrValidated { get; private set; }

        public bool FinalizeCalled { get; private set; }

        public Task<AcmeAccountResult> EnsureAccountAsync(
            AcmeAccountRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            workflowTrace.Add("acme:account");
            ExistingAccountObserved = request.ExistingAccount is not null;
            var account = request.ExistingAccount ?? new AcmeAccount(
                request.DirectoryUri,
                new Uri("https://acme.test/account/1"),
                "fixture-account-key"u8);
            return Task.FromResult(
                new AcmeAccountResult(
                    account,
                    AcmeResourceStatus.Valid,
                    Created: request.ExistingAccount is null));
        }

        public Task<AcmeOrder> CreateOrderAsync(
            AcmeAccount account,
            AcmeOrderRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            workflowTrace.Add("acme:order");
            dnsNames = request.DnsIdentifiers;
            return Task.FromResult(CreateOrder(AcmeResourceStatus.Pending));
        }

        public Task<AcmeOrder> GetOrderAsync(
            AcmeAccount account,
            Uri orderUri,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(CreateOrder(AcmeResourceStatus.Pending));
        }

        public Task<IReadOnlyList<AcmeHttp01Challenge>> GetHttp01ChallengesAsync(
            AcmeAccount account,
            Uri orderUri,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyList<AcmeHttp01Challenge> challenges = dnsNames
                .Select(
                    (dnsName, index) => new AcmeHttp01Challenge(
                        dnsName,
                        IsWildcard: false,
                        new Uri($"https://acme.test/auth/{index}"),
                        new Uri($"https://acme.test/challenge/{index}"),
                        $"token-{index}",
                        $"token-{index}.fixture-thumbprint",
                        AcmeResourceStatus.Pending,
                        null,
                        null))
                .ToArray();
            return Task.FromResult(challenges);
        }

        public Task<AcmeChallenge> AnswerHttp01ChallengeAsync(
            AcmeAccount account,
            AcmeHttp01Challenge challenge,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnswerCalls++;
            workflowTrace.Add($"acme:answer:{challenge.Identifier}");
            if (ThrowWhenAnswering)
            {
                throw new InvalidOperationException(
                    "Fake ACME detail that must be sanitized.");
            }

            return Task.FromResult(
                new AcmeChallenge(
                    challenge.ChallengeUri,
                    AcmeResourceStatus.Processing,
                    null,
                    null));
        }

        public Task<AcmeChallengePollResult> PollHttp01ChallengeAsync(
            AcmeAccount account,
            AcmeHttp01Challenge challenge,
            AcmePollingPolicy? policy = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(
                new AcmeChallengePollResult(
                    new AcmeChallenge(
                        challenge.ChallengeUri,
                        AcmeResourceStatus.Valid,
                        DateTimeOffset.UtcNow,
                        null),
                    Attempts: 1,
                    TimedOut: false));
        }

        public Task<AcmeOrder> FinalizeOrderAsync(
            AcmeAccount account,
            Uri orderUri,
            ReadOnlyMemory<byte> certificateSigningRequestDer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            workflowTrace.Add("acme:finalize");
            FinalizeCalled = true;
            var signingRequest = CertificateRequest.LoadSigningRequest(
                certificateSigningRequestDer.ToArray(),
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                signerSignaturePadding: null);
            var subjectAlternativeNames = signingRequest
                .CertificateExtensions
                .OfType<X509SubjectAlternativeNameExtension>()
                .Single();
            var observedDnsNames = subjectAlternativeNames
                .EnumerateDnsNames()
                .ToArray();
            var serverAuthentication = signingRequest
                .CertificateExtensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .Single()
                .EnhancedKeyUsages
                .Cast<Oid>()
                .Any(
                    static oid =>
                        oid.Value == "1.3.6.1.5.5.7.3.1");
            CsrValidated =
                signingRequest.PublicKey.Oid.Value ==
                "1.2.840.10045.2.1" &&
                new HashSet<string>(
                    observedDnsNames,
                    StringComparer.OrdinalIgnoreCase)
                .SetEquals(dnsNames) &&
                serverAuthentication;
            try
            {
                using var certificateAuthorityKey = ECDsa.Create(
                    ECCurve.NamedCurves.nistP256);
                var certificateAuthorityRequest = new CertificateRequest(
                    "CN=CertBaton Fake Test CA",
                    certificateAuthorityKey,
                    HashAlgorithmName.SHA256);
                certificateAuthorityRequest.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(
                        certificateAuthority: true,
                        hasPathLengthConstraint: false,
                        pathLengthConstraint: 0,
                        critical: true));
                certificateAuthorityRequest.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.KeyCertSign,
                        critical: true));
                using var certificateAuthority = certificateAuthorityRequest
                    .CreateSelfSigned(
                        DateTimeOffset.UtcNow.AddDays(-1),
                        DateTimeOffset.UtcNow.AddYears(1));
                using var issuedCertificate = signingRequest.Create(
                    certificateAuthority,
                    DateTimeOffset.UtcNow.AddMinutes(-5),
                    DateTimeOffset.UtcNow.AddDays(30),
                    RandomNumberGenerator.GetBytes(16));
                certificatePem = issuedCertificate.ExportCertificatePem();
            }
            catch (Exception exception)
            {
                workflowTrace.Add(
                    $"fake-finalize-error:{exception.GetType().Name}:{exception.Message}");
                throw;
            }
            return Task.FromResult(
                CreateOrder(AcmeResourceStatus.Processing));
        }

        public Task<AcmeOrderPollResult> PollOrderAsync(
            AcmeAccount account,
            Uri orderUri,
            AcmePollingPolicy? policy = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(
                new AcmeOrderPollResult(
                    CreateOrder(AcmeResourceStatus.Valid),
                    Attempts: 1,
                    TimedOut: false));
        }

        public Task<AcmeCertificateChain> DownloadCertificateAsync(
            AcmeAccount account,
            Uri orderUri,
            string? preferredChain = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (certificatePem is null)
            {
                throw new InvalidOperationException(
                    "The fake order has not been finalized.");
            }

            return Task.FromResult(
                new AcmeCertificateChain(
                    certificatePem,
                    [],
                    certificatePem));
        }

        private AcmeOrder CreateOrder(AcmeResourceStatus status) =>
            new(
                new Uri("https://acme.test/order/1"),
                dnsNames,
                status,
                DateTimeOffset.UtcNow.AddHours(1),
                null);
    }

    private sealed class FakeRemoteSessionFactory(
        FakeRemoteSession session,
        List<string> trace) : IRemoteSshSessionFactory
    {
        private readonly FakeRemoteSession remoteSession = session;
        private readonly List<string> workflowTrace = trace;

        public async ValueTask<IRemoteSshSession> ConnectAsync(
            RemoteSshConnectionOptions options,
            RemotePrivateKeyMaterial privateKey,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            workflowTrace.Add("ssh:connect:start");
            await using var keyStream = privateKey.OpenReadStream();
            using var buffer = new MemoryStream();
            await keyStream.CopyToAsync(buffer, cancellationToken);
            workflowTrace.Add($"ssh:key-length:{buffer.Length}");
            if (buffer.Length == 0)
            {
                throw new InvalidOperationException("Empty fake SSH key.");
            }

            workflowTrace.Add("ssh:connect");
            return remoteSession;
        }
    }

    private sealed class FakeRemoteSession(
        RemoteSshEndpoint endpoint,
        List<string> trace) : IRemoteSshSession
    {
        private readonly object sync = new();
        private readonly Dictionary<string, byte[]> files =
            new(StringComparer.Ordinal);
        private readonly List<string> workflowTrace = trace;
        private int currentRemovalConcurrency;
        private int maximumRemovalConcurrency;

        public RemoteSshEndpoint Endpoint { get; } = endpoint;

        public List<RemotePosixPath> RemovedPaths { get; } = [];

        public List<RemoteHelperVerbV1> HelperVerbs { get; } = [];

        public RemoteHelperVerbV1? FailingVerb { get; set; }

        public Exception? UploadException { get; set; }

        public string? PrepareOutput { get; set; }

        public bool FailChallengeRemoval { get; set; }

        public TimeSpan ChallengeRemovalDelay { get; set; }

        public int MaximumRemovalConcurrency =>
            Volatile.Read(ref maximumRemovalConcurrency);

        public Action<RemoteHelperVerbV1>? AfterHelper { get; set; }

        public Task<bool> FileExistsAsync(
            RemotePosixPath path,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(files.ContainsKey(path.Value));
        }

        public async Task UploadFileAsync(
            RemotePosixPath path,
            Stream content,
            RemoteWriteMode writeMode,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            workflowTrace.Add($"upload:{path.Value}");
            if (UploadException is not null)
            {
                throw UploadException;
            }

            if (writeMode == RemoteWriteMode.CreateNew &&
                files.ContainsKey(path.Value))
            {
                throw new IOException("File already exists.");
            }

            using var copy = new MemoryStream();
            await content.CopyToAsync(copy, cancellationToken);
            files[path.Value] = copy.ToArray();
        }

        public Task<byte[]> ReadFileAsync(
            RemotePosixPath path,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(files[path.Value].ToArray());
        }

        public Task<RemoteFileSha256> ComputeSha256Async(
            RemotePosixPath path,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var bytes = files[path.Value];
            return Task.FromResult(
                new RemoteFileSha256(
                    Convert.ToHexString(SHA256.HashData(bytes)),
                    bytes.LongLength));
        }

        public async Task RemoveFileAsync(
            RemotePosixPath path,
            MissingFileBehavior missingFileBehavior,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var isChallenge = path.Value.StartsWith(
                "/var/www/challenges/",
                StringComparison.Ordinal);
            var concurrency = Interlocked.Increment(
                ref currentRemovalConcurrency);
            UpdateMaximum(ref maximumRemovalConcurrency, concurrency);
            try
            {
                if (isChallenge && ChallengeRemovalDelay > TimeSpan.Zero)
                {
                    await Task.Delay(
                        ChallengeRemovalDelay,
                        cancellationToken);
                }

                if (FailChallengeRemoval && isChallenge)
                {
                    throw new IOException(
                        "Simulated challenge cleanup failure.");
                }

                lock (sync)
                {
                    var removed = files.Remove(path.Value);
                    if (!removed &&
                        missingFileBehavior == MissingFileBehavior.Fail)
                    {
                        throw new FileNotFoundException();
                    }

                    RemovedPaths.Add(path);
                    workflowTrace.Add($"remove:{path.Value}");
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

        public Task<RemoteHelperResult> InvokeHelperAsync(
            RemoteHelperVerbV1 verb,
            RemoteTransactionId transactionId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            HelperVerbs.Add(verb);
            workflowTrace.Add($"helper:{verb}");
            var result = new RemoteHelperResult(
                verb == FailingVerb ? 1 : 0,
                null,
                verb == RemoteHelperVerbV1.Prepare
                    ? PrepareOutput ?? JsonSerializer.Serialize(
                        new
                        {
                            version = 1,
                            success = true,
                            code = "helper.prepared",
                            transactionId = transactionId.ToString(),
                            uploadPath =
                                $"/srv/certbaton/incoming/{transactionId}",
                        })
                    : string.Empty,
                string.Empty);
            AfterHelper?.Invoke(verb);
            return Task.FromResult(result);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeHttp01Verifier : IPublicHttp01Verifier
    {
        public bool Success { get; set; } = true;

        public string Code { get; set; } = "http01.verified";

        public Task<Http01VerificationResult> VerifyAsync(
            Http01VerificationRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(
                new Http01VerificationResult(
                    Success,
                    Code,
                    request.ChallengeUri,
                    System.Net.HttpStatusCode.OK,
                    RedirectCount: 0,
                    [IPAddress.Parse("203.0.113.20")]));
        }
    }

    private sealed class FakeTlsVerifier : IPublicTlsVerifier
    {
        private readonly object sync = new();
        private int activeRequests;
        private int maximumConcurrency;

        public bool Success { get; set; } = true;

        public string Code { get; set; } = "tls.verified";

        public PublicTlsVerificationRequest? LastRequest { get; private set; }

        public List<PublicTlsVerificationRequest> Requests { get; } = [];

        public TimeSpan Delay { get; set; }

        public int MaximumConcurrency => Volatile.Read(ref maximumConcurrency);

        public async Task<PublicTlsVerificationResult> VerifyAsync(
            PublicTlsVerificationRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var concurrency = Interlocked.Increment(ref activeRequests);
            _ = InterlockedExtensions.Max(ref maximumConcurrency, concurrency);
            try
            {
                if (Delay > TimeSpan.Zero)
                {
                    await Task.Delay(Delay, cancellationToken);
                }

                lock (sync)
                {
                    LastRequest = request;
                    Requests.Add(request);
                }

                return new PublicTlsVerificationResult(
                    Success,
                    Code,
                    request.ExpectedLeafSha256,
                    DateTimeOffset.UtcNow.AddHours(-1),
                    DateTimeOffset.UtcNow.AddDays(30),
                    HostnameMatched: true,
                    ChainTrusted:
                        request.TrustPolicy == TlsTrustPolicy.System,
                    [IPAddress.Parse("203.0.113.20")]);
            }
            finally
            {
                _ = Interlocked.Decrement(ref activeRequests);
            }
        }
    }

    private static class InterlockedExtensions
    {
        public static int Max(ref int location, int value)
        {
            while (true)
            {
                var observed = Volatile.Read(ref location);
                if (observed >= value)
                {
                    return observed;
                }

                if (Interlocked.CompareExchange(ref location, value, observed) ==
                    observed)
                {
                    return value;
                }
            }
        }
    }

    private sealed class FakeCertificateInspector :
        ICertificateMaterialInspector
    {
        public CertificateInspectionResult Inspect(
            string certificateChainPem,
            string privateKeyPem,
            string expectedHostname,
            DateTimeOffset nowUtc)
        {
            using var certificate = X509Certificate2.CreateFromPem(
                certificateChainPem,
                privateKeyPem);
            return new CertificateInspectionResult(
                Success: true,
                "certificate.verified",
                certificate.GetCertHashString(HashAlgorithmName.SHA256),
                new DateTimeOffset(
                    certificate.NotBefore.ToUniversalTime()),
                new DateTimeOffset(
                    certificate.NotAfter.ToUniversalTime()));
        }
    }
}

internal static class ReadOnlyListExtensions
{
    public static int IndexOf<T>(
        this IReadOnlyList<T> values,
        T value)
    {
        for (var index = 0; index < values.Count; index++)
        {
            if (EqualityComparer<T>.Default.Equals(values[index], value))
            {
                return index;
            }
        }

        return -1;
    }
}
