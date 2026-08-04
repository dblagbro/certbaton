using CertBaton.Contracts;
using CertBaton.Desktop;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class MainWindowLiveViewModelTests
{
    private static readonly DateTimeOffset operationStart =
        new(2026, 7, 31, 14, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public async Task EmptyTargetListShowsUiEnrollmentGuidance()
    {
        var viewModel = CreateViewModel(
            new TargetListSnapshot(Array.Empty<TargetSnapshot>()),
            static (_, _, _) => throw new AssertFailedException(
                "A renewal must not start without a target."),
            static (_, _) => throw new AssertFailedException(
                "A renewal must not be queried without an accepted operation."));

        await viewModel.RefreshCommand.ExecuteAsync(null);

        Assert.IsEmpty(viewModel.Targets);
        Assert.IsNull(viewModel.SelectedTarget);
        Assert.AreEqual("No websites yet", viewModel.LiveStatus);
        StringAssert.Contains(
            viewModel.LiveSummary,
            "Add website");
        Assert.IsFalse(viewModel.StartRenewalCommand.CanExecute(null));
    }

    [TestMethod]
    public async Task StartPollsAcceptedOperationAndDisplaysVerifiedEvidence()
    {
        var target = CreateTarget();
        var operationId = Guid.Parse("019c10d7-0b75-7bb2-a20a-e6078edaaad1");
        var queued = CreateOperation(operationId, target.TargetId, "queued");
        var succeeded = CreateOperation(
            operationId,
            target.TargetId,
            "succeeded",
            certificateFingerprint: "A1B2C3D4",
            publicTlsVerified: true,
            challengeCleanupVerified: true,
            evidence:
            [
                CreateEvidence(
                    1,
                    "verification",
                    "public-tls",
                    "succeeded",
                    "tls.public_verified"),
                CreateEvidence(
                    2,
                    "cleanup",
                    "http-01",
                    "succeeded",
                    "challenge.cleanup_verified"),
            ]);
        Guid observedTargetId = Guid.Empty;
        Guid observedIdempotencyKey = Guid.Empty;
        var queriedOperationIds = new List<Guid>();
        var viewModel = CreateViewModel(
            new TargetListSnapshot([target]),
            (targetId, idempotencyKey, cancellationToken) =>
            {
                Assert.IsFalse(cancellationToken.IsCancellationRequested);
                observedTargetId = targetId;
                observedIdempotencyKey = idempotencyKey;
                return Task.FromResult(
                    IpcResponse.Succeeded(Guid.NewGuid(), queued));
            },
            (queriedOperationId, cancellationToken) =>
            {
                Assert.IsFalse(cancellationToken.IsCancellationRequested);
                queriedOperationIds.Add(queriedOperationId);
                return Task.FromResult(
                    IpcResponse.Succeeded(Guid.NewGuid(), succeeded));
            });

        await viewModel.RefreshCommand.ExecuteAsync(null);
        await viewModel.StartRenewalCommand.ExecuteAsync(null);

        Assert.AreEqual(target.TargetId, observedTargetId);
        Assert.AreNotEqual(Guid.Empty, observedIdempotencyKey);
        CollectionAssert.AreEqual(
            new[] { operationId },
            queriedOperationIds);
        Assert.AreEqual("Succeeded", viewModel.LiveStatus);
        Assert.AreEqual(operationId.ToString("D"), viewModel.LiveOperationId);
        Assert.AreEqual("Verified", viewModel.LivePublicTls);
        Assert.AreEqual("Verified", viewModel.LiveChallengeCleanup);
        Assert.AreEqual("A1B2C3D4", viewModel.LiveCertificateFingerprint);
        Assert.HasCount(2, viewModel.LiveTimeline);
        Assert.AreEqual("Public Tls", viewModel.LiveTimeline[0].Action);
        Assert.AreEqual("Cleanup", viewModel.LiveTimeline[1].Category);
    }

    [TestMethod]
    public async Task FailedOperationShowsFailureAndUnverifiedOutcomes()
    {
        var target = CreateTarget();
        var failed = CreateOperation(
            Guid.Parse("019c10d8-2cd0-7b8a-a1df-bac44604d8a6"),
            target.TargetId,
            "failed",
            failureCode: "tls.verification_failed",
            evidence:
            [
                CreateEvidence(
                    1,
                    "verification",
                    "public-tls",
                    "failed",
                    "tls.verification_failed"),
            ]);
        var viewModel = CreateViewModel(
            new TargetListSnapshot([target]),
            (_, _, _) => Task.FromResult(
                IpcResponse.Succeeded(Guid.NewGuid(), failed)),
            static (_, _) => throw new AssertFailedException(
                "A terminal operation must not be polled."));

        await viewModel.RefreshCommand.ExecuteAsync(null);
        await viewModel.StartRenewalCommand.ExecuteAsync(null);

        Assert.AreEqual("Failed", viewModel.LiveStatus);
        Assert.AreEqual("tls.verification_failed", viewModel.LiveFailureCode);
        Assert.AreEqual("Not verified", viewModel.LivePublicTls);
        Assert.AreEqual("Not verified", viewModel.LiveChallengeCleanup);
        StringAssert.Contains(viewModel.LiveSummary, "tls.verification_failed");
        Assert.HasCount(1, viewModel.LiveTimeline);
    }

    [TestMethod]
    public async Task AmbiguousStartRetryReusesPerTargetIdempotencyKey()
    {
        var target = CreateTarget();
        var completed = CreateOperation(
            Guid.Parse("019c10d9-56d5-7fa8-8bbc-1e663c96536c"),
            target.TargetId,
            "succeeded",
            certificateFingerprint: "FFEEDDCC",
            publicTlsVerified: true,
            challengeCleanupVerified: true);
        var observedKeys = new List<Guid>();
        var attempt = 0;
        var viewModel = CreateViewModel(
            new TargetListSnapshot([target]),
            (_, idempotencyKey, _) =>
            {
                observedKeys.Add(idempotencyKey);
                attempt++;
                return attempt == 1
                    ? Task.FromException<IpcResponse>(
                        new TimeoutException("The response was ambiguous."))
                    : Task.FromResult(
                        IpcResponse.Succeeded(Guid.NewGuid(), completed));
            },
            static (_, _) => throw new AssertFailedException(
                "A completed operation must not be polled."));

        await viewModel.RefreshCommand.ExecuteAsync(null);
        await viewModel.StartRenewalCommand.ExecuteAsync(null);

        StringAssert.Contains(
            viewModel.LiveSummary,
            "reuse the same renewal request identity");

        await viewModel.StartRenewalCommand.ExecuteAsync(null);

        Assert.HasCount(2, observedKeys);
        Assert.AreNotEqual(Guid.Empty, observedKeys[0]);
        Assert.AreEqual(observedKeys[0], observedKeys[1]);
        Assert.AreEqual("Succeeded", viewModel.LiveStatus);
    }

    [TestMethod]
    public async Task PollingRejectsMismatchedOperationWithoutReplacingAcceptedEvidence()
    {
        var target = CreateTarget();
        var acceptedOperationId =
            Guid.Parse("019c10da-5d2a-7d09-92b0-92c7f67bbf91");
        var accepted = CreateOperation(
            acceptedOperationId,
            target.TargetId,
            "queued");
        var otherOperation = CreateOperation(
            Guid.Parse("019c10db-481e-70e8-862e-ad11ab5b4cce"),
            target.TargetId,
            "running",
            evidence:
            [
                CreateEvidence(
                    1,
                    "challenge",
                    "publish",
                    "succeeded",
                    "other.challenge_published"),
            ]);
        Guid queriedOperationId = Guid.Empty;
        var viewModel = CreateViewModel(
            new TargetListSnapshot([target]),
            (_, _, _) => Task.FromResult(
                IpcResponse.Succeeded(Guid.NewGuid(), accepted)),
            (operationId, _) =>
            {
                queriedOperationId = operationId;
                return Task.FromResult(
                    IpcResponse.Succeeded(Guid.NewGuid(), otherOperation));
            });

        await viewModel.RefreshCommand.ExecuteAsync(null);
        await viewModel.StartRenewalCommand.ExecuteAsync(null);

        Assert.AreEqual(acceptedOperationId, queriedOperationId);
        Assert.AreEqual("Renewal response mismatch", viewModel.LiveStatus);
        Assert.AreEqual(
            acceptedOperationId.ToString("D"),
            viewModel.LiveOperationId);
        StringAssert.Contains(
            viewModel.LiveSummary,
            acceptedOperationId.ToString("D"));
        Assert.IsEmpty(viewModel.LiveTimeline);
        Assert.IsFalse(
            viewModel.LiveSummary.Contains(
                otherOperation.OperationId.ToString("D"),
                StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task ForbiddenTargetListShowsAdministratorState()
    {
        var viewModel = CreateViewModel(
            IpcResponse.Failed(
                Guid.NewGuid(),
                "target_list_forbidden",
                "The caller is not authorized."));

        await viewModel.RefreshCommand.ExecuteAsync(null);

        Assert.AreEqual(
            "Administrator approval required",
            viewModel.LiveStatus);
        StringAssert.Contains(viewModel.LiveSummary, "elevated administrator");
        Assert.IsFalse(viewModel.StartRenewalCommand.CanExecute(null));
    }

    private static MainWindowViewModel CreateViewModel(
        TargetListSnapshot targetList,
        Func<Guid, Guid, CancellationToken, Task<IpcResponse>> startRenewalAsync,
        Func<Guid, CancellationToken, Task<IpcResponse>> getRenewalAsync) =>
        CreateViewModel(
            IpcResponse.Succeeded(Guid.NewGuid(), targetList),
            startRenewalAsync,
            getRenewalAsync);

    private static MainWindowViewModel CreateViewModel(
        IpcResponse targetListResponse,
        Func<Guid, Guid, CancellationToken, Task<IpcResponse>>?
            startRenewalAsync = null,
        Func<Guid, CancellationToken, Task<IpcResponse>>?
            getRenewalAsync = null) =>
        new(
            static _ => Task.FromResult(
                IpcResponse.Succeeded(
                    Guid.NewGuid(),
                    new HealthSnapshot(
                        "healthy",
                        "test",
                        operationStart,
                        operationStart))),
            _ => Task.FromResult(targetListResponse),
            startRenewalAsync ??
                (static (_, _, _) => throw new AssertFailedException(
                    "A renewal was not expected.")),
            getRenewalAsync ??
                (static (_, _) => throw new AssertFailedException(
                    "A renewal query was not expected.")),
            static _ => Task.FromResult(
                IpcResponse.Failed(
                    Guid.NewGuid(),
                    "simulation_not_found",
                    "No simulation exists.")),
            static (_, _, _) => throw new AssertFailedException(
                "A simulation was not expected."),
            static (_, _) => Task.CompletedTask);

    private static TargetSnapshot CreateTarget() =>
        new(
            Guid.Parse("019c10d5-ffec-70ca-ad1c-255bc47f05f7"),
            "Staging web server",
            ["www2.example.test"],
            "ssh.example.test",
            22,
            "certbaton",
            "ssh-ed25519",
            "SHA256:test-host-key-pin",
            LiveContractValues.LetsEncryptStaging,
            true,
            operationStart.AddDays(30),
            "ready");

    private static RenewalOperationSnapshot CreateOperation(
        Guid operationId,
        Guid targetId,
        string status,
        string? failureCode = null,
        string? certificateFingerprint = null,
        bool publicTlsVerified = false,
        bool challengeCleanupVerified = false,
        IReadOnlyList<RenewalEvidenceSnapshot>? evidence = null) =>
        new(
            operationId,
            targetId,
            status,
            operationStart,
            operationStart.AddMinutes(1),
            status is "queued" or "running"
                ? null
                : operationStart.AddMinutes(1),
            failureCode,
            certificateFingerprint,
            publicTlsVerified,
            challengeCleanupVerified,
            evidence ?? Array.Empty<RenewalEvidenceSnapshot>());

    private static RenewalEvidenceSnapshot CreateEvidence(
        long sequence,
        string category,
        string action,
        string outcome,
        string code) =>
        new(
            sequence,
            category,
            action,
            outcome,
            operationStart.AddSeconds(sequence),
            code,
            $"Recorded {code}.");
}
