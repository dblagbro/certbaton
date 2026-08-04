using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using CertBaton.Application.Acme;
using CertBaton.Application.Live;
using CertBaton.Application.Persistence;
using CertBaton.Application.Remote;
using CertBaton.Application.Security;
using CertBaton.Application.Verification;
using CertBaton.Domain.Operations;

namespace CertBaton.Service;

public sealed class ProductionLiveRenewalExecutor : ILiveRenewalExecutor
{
    private const int MaximumParallelCleanupOperations = 8;
    private const int MaximumParallelTlsVerifications = 8;
    private static readonly JsonSerializerOptions helperJsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };
    private readonly IProductionStore productionStore;
    private readonly IAcmeEngine acmeEngine;
    private readonly IAcmeAccountStore accountStore;
    private readonly ICertificatePrivateKeyStore certificatePrivateKeyStore;
    private readonly IIssuedCertificateStore issuedCertificateStore;
    private readonly IRemoteSshSessionFactory remoteSessionFactory;
    private readonly ISecretVault secretVault;
    private readonly IPublicHttp01Verifier http01Verifier;
    private readonly IPublicTlsVerifier tlsVerifier;
    private readonly ICertificateMaterialInspector certificateInspector;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan recoveryPhaseTimeout;

    public ProductionLiveRenewalExecutor(
        IProductionStore productionStore,
        IAcmeEngine acmeEngine,
        IAcmeAccountStore accountStore,
        ICertificatePrivateKeyStore certificatePrivateKeyStore,
        IIssuedCertificateStore issuedCertificateStore,
        IRemoteSshSessionFactory remoteSessionFactory,
        ISecretVault secretVault,
        IPublicHttp01Verifier http01Verifier,
        IPublicTlsVerifier tlsVerifier,
        ICertificateMaterialInspector certificateInspector,
        TimeProvider timeProvider,
        TimeSpan? recoveryPhaseTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(productionStore);
        ArgumentNullException.ThrowIfNull(acmeEngine);
        ArgumentNullException.ThrowIfNull(accountStore);
        ArgumentNullException.ThrowIfNull(certificatePrivateKeyStore);
        ArgumentNullException.ThrowIfNull(issuedCertificateStore);
        ArgumentNullException.ThrowIfNull(remoteSessionFactory);
        ArgumentNullException.ThrowIfNull(secretVault);
        ArgumentNullException.ThrowIfNull(http01Verifier);
        ArgumentNullException.ThrowIfNull(tlsVerifier);
        ArgumentNullException.ThrowIfNull(certificateInspector);
        ArgumentNullException.ThrowIfNull(timeProvider);
        var normalizedRecoveryPhaseTimeout =
            recoveryPhaseTimeout ?? TimeSpan.FromSeconds(30);
        if (normalizedRecoveryPhaseTimeout < TimeSpan.FromSeconds(1) ||
            normalizedRecoveryPhaseTimeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(
                nameof(recoveryPhaseTimeout),
                normalizedRecoveryPhaseTimeout,
                "The recovery phase timeout must be between one second and five minutes.");
        }
        this.productionStore = productionStore;
        this.acmeEngine = acmeEngine;
        this.accountStore = accountStore;
        this.certificatePrivateKeyStore = certificatePrivateKeyStore;
        this.issuedCertificateStore = issuedCertificateStore;
        this.remoteSessionFactory = remoteSessionFactory;
        this.secretVault = secretVault;
        this.http01Verifier = http01Verifier;
        this.tlsVerifier = tlsVerifier;
        this.certificateInspector = certificateInspector;
        this.timeProvider = timeProvider;
        this.recoveryPhaseTimeout = normalizedRecoveryPhaseTimeout;
    }

    public Task<LiveRenewalResult> RunAsync(
        OperationId operationId,
        Guid executionEpoch,
        LiveHttp01RenewalRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.OperationId != operationId.Value)
        {
            throw new ArgumentException(
                "The renewal request and durable operation identifiers do not match.",
                nameof(request));
        }

        var journal = new ProductionLiveRenewalJournal(
            productionStore,
            operationId,
            executionEpoch);
        var coordinator = new LiveHttp01RenewalCoordinator(
            acmeEngine,
            accountStore,
            certificatePrivateKeyStore,
            issuedCertificateStore,
            remoteSessionFactory,
            secretVault,
            http01Verifier,
            tlsVerifier,
            certificateInspector,
            journal,
            timeProvider);
        return coordinator.RunAsync(request, cancellationToken);
    }

    public async Task<LiveRenewalResult> RecoverAsync(
        OperationId operationId,
        Guid executionEpoch,
        LiveHttp01RenewalRequest request,
        CancellationToken cancellationToken)
    {
        ValidateOperationRequest(operationId, request);
        var artifact = productionStore.FindCertificateArtifact(operationId);
        var evidence = productionStore.ReadOperationEvidence(operationId);
        var cleanupVerified = evidence.Any(
            static item =>
                item.Kind == OperationEvidenceKind.Cleanup &&
                item.Outcome == OperationEvidenceOutcome.Succeeded &&
                item.Code == "challenge.cleanup_complete");
        var intents = productionStore.ReadOperationIntents(operationId);
        var sequence = intents.Count == 0
            ? 0
            : intents.Max(static intent => intent.Sequence);
        var journal = new ProductionLiveRenewalJournal(
            productionStore,
            operationId,
            executionEpoch);
        var recoveryJournal = new RecoveryJournalWriter(
            journal,
            operationId,
            sequence,
            timeProvider);

        await using var session = await ConnectAsync(request, cancellationToken)
            .ConfigureAwait(false);
        var challengeCleanup = await ReconcileChallengeWritesAsync(
                operationId,
                executionEpoch,
                session,
                intents,
                cleanupVerified,
                request.ChallengeWebroot,
                recoveryJournal,
                cancellationToken)
            .ConfigureAwait(false);
        cleanupVerified = challengeCleanup.Verified;
        intents = productionStore.ReadOperationIntents(operationId);
        var transactionId = new RemoteTransactionId(operationId.Value);
        RemoteHelperResult statusResult;
        try
        {
            using var statusPhase = CreateRecoveryPhaseTokenSource(
                cancellationToken);
            statusResult = await session
                    .InvokeHelperAsync(
                        RemoteHelperVerbV1.Status,
                        transactionId,
                        statusPhase.Token)
                    .ConfigureAwait(false);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return CreateRecoveryResult(
                operationId,
                LiveRenewalStatus.Blocked,
                "recovery.status_failed",
                cleanupVerified,
                publicTlsVerified: false,
                activationAttempted: intents.Any(
                    static intent =>
                        intent.Kind == OperationIntentKind.Activate),
                rollbackAttempted: false,
                rollbackSucceeded: false,
                artifact,
                request);
        }
        if (!statusResult.Succeeded)
        {
            var helperCode = TryReadHelperFailureCode(statusResult.StandardError);
            var activationWasPlanned = intents.Any(
                static intent => intent.Kind == OperationIntentKind.Activate);
            var recoveryStatus = activationWasPlanned
                ? LiveRenewalStatus.RollbackRequired
                : helperCode == "helper.state_missing" &&
                    !challengeCleanup.Required
                    ? LiveRenewalStatus.Failed
                    : LiveRenewalStatus.Blocked;
            return CreateRecoveryResult(
                operationId,
                recoveryStatus,
                challengeCleanup.Required
                    ? "recovery.challenge_cleanup_required"
                    : helperCode == "helper.state_missing"
                        ? "recovery.transaction_missing"
                        : "recovery.status_failed",
                cleanupVerified,
                publicTlsVerified: false,
                activationAttempted:
                    activationWasPlanned,
                rollbackAttempted: false,
                rollbackSucceeded: false,
                artifact,
                request);
        }

        var helperStatus = ParseHelperStatus(
            statusResult.StandardOutput,
            transactionId);
        switch (helperStatus.Status)
        {
            case "prepared":
            case "validated":
                {
                    await recoveryJournal.AppendAsync(
                            LiveRenewalJournalCategory.Intent,
                            LiveRenewalJournalAction.Abort,
                            LiveRenewalJournalOutcome.Planned,
                            "abort.planned",
                            "Restart recovery will discard the unactivated remote transaction.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    var aborted = await InvokeHelperWithPhaseAsync(
                            session,
                            RemoteHelperVerbV1.Abort,
                            transactionId,
                            cancellationToken)
                        .ConfigureAwait(false);
                    await recoveryJournal.AppendAsync(
                            LiveRenewalJournalAction.Abort,
                            aborted
                                ? LiveRenewalJournalOutcome.Succeeded
                                : LiveRenewalJournalOutcome.Failed,
                            aborted ? "abort.succeeded" : "abort.failed",
                            aborted
                                ? "Restart recovery discarded the unactivated remote transaction."
                                : "Restart recovery could not discard the unactivated remote transaction.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (aborted)
                    {
                        ReconcileIntentKind(
                            operationId,
                            executionEpoch,
                            OperationIntentKind.Abort);
                    }
                    return CreateRecoveryResult(
                        operationId,
                        aborted && !challengeCleanup.Required
                            ? LiveRenewalStatus.Failed
                            : LiveRenewalStatus.Blocked,
                        !aborted
                            ? "recovery.abort_required"
                            : challengeCleanup.Required
                                ? "recovery.challenge_cleanup_required"
                                : "recovery.unactivated_aborted",
                        cleanupVerified,
                        publicTlsVerified: false,
                        activationAttempted: false,
                        rollbackAttempted: false,
                        rollbackSucceeded: false,
                        artifact,
                        request);
                }

            case "aborted":
                ReconcileIntentKind(
                    operationId,
                    executionEpoch,
                    OperationIntentKind.Abort);
                return CreateRecoveryResult(
                    operationId,
                    challengeCleanup.Required
                        ? LiveRenewalStatus.Blocked
                        : LiveRenewalStatus.Failed,
                    challengeCleanup.Required
                        ? "recovery.challenge_cleanup_required"
                        : "recovery.transaction_aborted",
                    cleanupVerified,
                    publicTlsVerified: false,
                    activationAttempted: false,
                    rollbackAttempted: false,
                    rollbackSucceeded: false,
                    artifact,
                    request);

            case "rolled-back":
                ReconcileIntentKind(
                    operationId,
                    executionEpoch,
                    OperationIntentKind.Rollback);
                var rolledBackAbortVerified = await AbortAfterRollbackAsync(
                        operationId,
                        executionEpoch,
                        session,
                        recoveryJournal,
                        cancellationToken)
                    .ConfigureAwait(false);
                return CreateRecoveryResult(
                    operationId,
                    challengeCleanup.Required || !rolledBackAbortVerified
                        ? LiveRenewalStatus.Blocked
                        : LiveRenewalStatus.Failed,
                    !rolledBackAbortVerified
                        ? "recovery.abort_required"
                        : challengeCleanup.Required
                        ? "recovery.challenge_cleanup_required"
                        : "recovery.transaction_rolled_back",
                    cleanupVerified,
                    publicTlsVerified: false,
                    activationAttempted: true,
                    rollbackAttempted: true,
                    rollbackSucceeded: true,
                    artifact,
                    request);

            case "rolling-back":
                {
                    await recoveryJournal.AppendAsync(
                            LiveRenewalJournalCategory.Intent,
                            LiveRenewalJournalAction.Rollback,
                            LiveRenewalJournalOutcome.Planned,
                            "rollback.planned",
                            "Restart recovery will complete restoration of the prior certificate generation.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    var rolledBack = await InvokeHelperWithPhaseAsync(
                            session,
                            RemoteHelperVerbV1.Rollback,
                            transactionId,
                            cancellationToken)
                        .ConfigureAwait(false);
                    await recoveryJournal.AppendAsync(
                            LiveRenewalJournalAction.Rollback,
                            rolledBack
                                ? LiveRenewalJournalOutcome.Succeeded
                                : LiveRenewalJournalOutcome.Failed,
                            rolledBack ? "rollback.succeeded" : "rollback.failed",
                            rolledBack
                                ? "Restart recovery completed restoration of the prior certificate generation."
                                : "Restart recovery could not restore the prior certificate generation.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (rolledBack)
                    {
                        ReconcileIntentKind(
                            operationId,
                            executionEpoch,
                            OperationIntentKind.Rollback);
                    }
                    var abortVerified = rolledBack &&
                        await AbortAfterRollbackAsync(
                                operationId,
                                executionEpoch,
                                session,
                                recoveryJournal,
                                cancellationToken)
                            .ConfigureAwait(false);
                    return CreateRecoveryResult(
                        operationId,
                        rolledBack
                            ? challengeCleanup.Required || !abortVerified
                                ? LiveRenewalStatus.Blocked
                                : LiveRenewalStatus.Failed
                            : LiveRenewalStatus.RollbackRequired,
                        rolledBack
                            ? !abortVerified
                                ? "recovery.abort_required"
                                : challengeCleanup.Required
                                ? "recovery.challenge_cleanup_required"
                                : "recovery.rollback_completed"
                            : "recovery.rollback_failed",
                        cleanupVerified,
                        publicTlsVerified: false,
                        activationAttempted: true,
                        rollbackAttempted: true,
                        rollbackSucceeded: rolledBack,
                        artifact,
                        request);
                }

            case "activating":
                {
                    var activated = await InvokeHelperWithPhaseAsync(
                            session,
                            RemoteHelperVerbV1.Activate,
                            transactionId,
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (!activated)
                    {
                        return await RollbackAfterRecoveryFailureAsync(
                                operationId,
                                executionEpoch,
                                request,
                                artifact,
                                cleanupVerified,
                                session,
                                recoveryJournal,
                                "recovery.activation_failed",
                                cancellationToken)
                            .ConfigureAwait(false);
                    }

                    ReconcileIntentKind(
                        operationId,
                        executionEpoch,
                        OperationIntentKind.Activate);

                    goto case "active";
                }

            case "active":
            case "committed":
                {
                    ReconcileIntentKind(
                        operationId,
                        executionEpoch,
                        OperationIntentKind.Activate);
                    if (artifact is null || !cleanupVerified)
                    {
                        if (helperStatus.Status == "committed")
                        {
                            return CreateRecoveryResult(
                                operationId,
                                LiveRenewalStatus.Blocked,
                                artifact is null
                                    ? "recovery.committed_artifact_missing"
                                    : "recovery.challenge_cleanup_required",
                                cleanupVerified,
                                publicTlsVerified: false,
                                activationAttempted: true,
                                rollbackAttempted: false,
                                rollbackSucceeded: false,
                                artifact,
                                request);
                        }

                        return await RollbackAfterRecoveryFailureAsync(
                                operationId,
                                executionEpoch,
                                request,
                                artifact,
                                cleanupVerified,
                                session,
                                recoveryJournal,
                                artifact is null
                                    ? "recovery.artifact_missing"
                                    : "recovery.cleanup_unverified",
                                cancellationToken)
                            .ConfigureAwait(false);
                    }

                    if (!await InvokeHelperWithPhaseAsync(
                            session,
                            RemoteHelperVerbV1.Verify,
                            transactionId,
                            cancellationToken)
                        .ConfigureAwait(false))
                    {
                        if (helperStatus.Status == "committed")
                        {
                            return CreateRecoveryResult(
                                operationId,
                                LiveRenewalStatus.Blocked,
                                "recovery.committed_remote_verify_failed",
                                cleanupVerified,
                                publicTlsVerified: false,
                                activationAttempted: true,
                                rollbackAttempted: false,
                                rollbackSucceeded: false,
                                artifact,
                                request);
                        }

                        return await RollbackAfterRecoveryFailureAsync(
                                operationId,
                                executionEpoch,
                                request,
                                artifact,
                                cleanupVerified,
                                session,
                                recoveryJournal,
                                "recovery.remote_verify_failed",
                                cancellationToken)
                            .ConfigureAwait(false);
                    }

                    var tlsVerified = await VerifyEveryDnsNameAsync(
                            request,
                            artifact,
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (!tlsVerified)
                    {
                        if (helperStatus.Status == "committed")
                        {
                            return CreateRecoveryResult(
                                operationId,
                                LiveRenewalStatus.Blocked,
                                "recovery.committed_tls_verify_failed",
                                cleanupVerified,
                                publicTlsVerified: false,
                                activationAttempted: true,
                                rollbackAttempted: false,
                                rollbackSucceeded: false,
                                artifact,
                                request);
                        }

                        return await RollbackAfterRecoveryFailureAsync(
                                operationId,
                                executionEpoch,
                                request,
                                artifact,
                                cleanupVerified,
                                session,
                                recoveryJournal,
                                "recovery.tls_verify_failed",
                                cancellationToken)
                            .ConfigureAwait(false);
                    }

                    await recoveryJournal.AppendAsync(
                            LiveRenewalJournalAction.PublicTlsVerification,
                            LiveRenewalJournalOutcome.Succeeded,
                            "tls.all_names_verified",
                            "Restart recovery verified every configured DNS name against the expected certificate.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    await recoveryJournal.AppendAsync(
                            LiveRenewalJournalCategory.Intent,
                            LiveRenewalJournalAction.Commit,
                            LiveRenewalJournalOutcome.Planned,
                            "commit.planned",
                            helperStatus.Status == "committed"
                                ? "Restart recovery will idempotently re-commit the committed certificate generation."
                                : "Restart recovery will commit the verified certificate generation.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (!await InvokeHelperWithPhaseAsync(
                            session,
                            RemoteHelperVerbV1.Commit,
                            transactionId,
                            cancellationToken)
                        .ConfigureAwait(false))
                    {
                        return CreateRecoveryResult(
                            operationId,
                            helperStatus.Status == "committed"
                                ? LiveRenewalStatus.Blocked
                                : LiveRenewalStatus.RollbackRequired,
                            helperStatus.Status == "committed"
                                ? "recovery.committed_reconfirm_required"
                                : "recovery.commit_failed",
                            cleanupVerified,
                            publicTlsVerified: true,
                            activationAttempted: true,
                            rollbackAttempted: false,
                            rollbackSucceeded: false,
                            artifact,
                            request);
                    }

                    await recoveryJournal.AppendAsync(
                            LiveRenewalJournalAction.Commit,
                            LiveRenewalJournalOutcome.Applied,
                            "commit.applied",
                            "Restart recovery idempotently committed the verified certificate generation.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    ReconcileIntentKind(
                        operationId,
                        executionEpoch,
                        OperationIntentKind.Commit);

                    await recoveryJournal.AppendAsync(
                            LiveRenewalJournalAction.Terminal,
                            LiveRenewalJournalOutcome.Succeeded,
                            "renewal.succeeded",
                            "Restart recovery proved the committed deployment and completed the renewal.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    return CreateRecoveryResult(
                        operationId,
                        LiveRenewalStatus.Succeeded,
                        failureCode: null,
                        cleanupVerified,
                        publicTlsVerified: true,
                        activationAttempted: true,
                        rollbackAttempted: false,
                        rollbackSucceeded: false,
                        artifact,
                        request);
                }

            default:
                return CreateRecoveryResult(
                    operationId,
                    LiveRenewalStatus.RollbackRequired,
                    "recovery.status_unknown",
                    cleanupVerified,
                    publicTlsVerified: false,
                    activationAttempted: true,
                    rollbackAttempted: false,
                    rollbackSucceeded: false,
                    artifact,
                    request);
        }
    }

    private async Task<ChallengeCleanupRecovery> ReconcileChallengeWritesAsync(
        OperationId operationId,
        Guid executionEpoch,
        IRemoteSshSession session,
        IReadOnlyList<OperationIntent> intents,
        bool aggregateCleanupVerified,
        RemotePosixPath challengeWebroot,
        RecoveryJournalWriter recoveryJournal,
        CancellationToken cancellationToken)
    {
        var challengeWrites = intents
            .Where(
                static intent =>
                    intent.Kind == OperationIntentKind.ChallengeWrite)
            .ToArray();
        var cleanupCandidates =
            new List<(OperationIntent Intent, RemotePosixPath Path)>();
        foreach (var intent in challengeWrites.Where(
                     static intent =>
                         intent.Status != OperationIntentStatus.Reconciled))
        {
            if (intent.RemotePath is null)
            {
                await recoveryJournal.AppendAsync(
                        LiveRenewalJournalAction.ChallengeCleanup,
                        LiveRenewalJournalOutcome.Failed,
                        "challenge.cleanup_path_missing",
                        "Restart recovery cannot remove a legacy challenge write whose exact remote path was not persisted.",
                        cancellationToken)
                    .ConfigureAwait(false);
                continue;
            }

            try
            {
                var path = RemotePosixPath.Parse(intent.RemotePath);
                if (!IsDirectChallengeChild(path, challengeWebroot))
                {
                    await recoveryJournal.AppendWithSubjectAsync(
                            LiveRenewalJournalCategory.Evidence,
                            LiveRenewalJournalAction.ChallengeCleanup,
                            LiveRenewalJournalOutcome.Failed,
                            "challenge.cleanup_path_mismatch",
                            "Restart recovery rejected a persisted challenge path outside the enrolled challenge root.",
                            path.Value,
                            cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                cleanupCandidates.Add((intent, path));
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await recoveryJournal.AppendWithSubjectAsync(
                            LiveRenewalJournalCategory.Evidence,
                            LiveRenewalJournalAction.ChallengeCleanup,
                            LiveRenewalJournalOutcome.Failed,
                            "challenge.cleanup_failed",
                            "Restart recovery could not verifiably remove the temporary HTTP-01 challenge response.",
                            intent.RemotePath,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (Exception) when (!cancellationToken.IsCancellationRequested)
                {
                    // The unreconciled durable intent remains authoritative.
                }
            }
        }

        var cleanupOutcomes = new bool?[cleanupCandidates.Count];
        using (var overallCleanup = CreateScaledRecoveryPhaseTokenSource(
                   cleanupCandidates.Count,
                   MaximumParallelCleanupOperations,
                   cancellationToken))
        {
            try
            {
                await Parallel.ForEachAsync(
                        Enumerable.Range(0, cleanupCandidates.Count),
                        new ParallelOptions
                        {
                            MaxDegreeOfParallelism =
                                MaximumParallelCleanupOperations,
                            CancellationToken = overallCleanup.Token,
                        },
                        async (index, phaseCancellationToken) =>
                        {
                            using var filePhase =
                                CancellationTokenSource.CreateLinkedTokenSource(
                                    phaseCancellationToken);
                            filePhase.CancelAfter(recoveryPhaseTimeout);
                            try
                            {
                                await session.RemoveFileAsync(
                                        cleanupCandidates[index].Path,
                                        MissingFileBehavior.Ignore,
                                        filePhase.Token)
                                    .ConfigureAwait(false);
                                cleanupOutcomes[index] = true;
                            }
                            catch (Exception) when (
                                !cancellationToken.IsCancellationRequested)
                            {
                                cleanupOutcomes[index] = false;
                            }
                        })
                    .ConfigureAwait(false);
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                // Completed workers retained their result. Workers that could
                // not start inside the scaled overall budget remain blocked.
            }
        }

        for (var index = 0; index < cleanupCandidates.Count; index++)
        {
            var (intent, path) = cleanupCandidates[index];
            var removed = cleanupOutcomes[index] is true;
            try
            {
                using var evidencePhase = CreateRecoveryPhaseTokenSource(
                    cancellationToken);
                await recoveryJournal.AppendWithSubjectAsync(
                        LiveRenewalJournalCategory.Evidence,
                        LiveRenewalJournalAction.ChallengeCleanup,
                        removed
                            ? LiveRenewalJournalOutcome.Succeeded
                            : LiveRenewalJournalOutcome.Failed,
                        removed
                            ? "challenge.cleaned"
                            : cleanupOutcomes[index] is null
                                ? "challenge.cleanup_timeout"
                                : "challenge.cleanup_failed",
                        removed
                            ? "Restart recovery removed the temporary HTTP-01 challenge response."
                            : "Restart recovery could not verifiably remove the temporary HTTP-01 challenge response within the bounded cleanup phase.",
                        path.Value,
                        evidencePhase.Token)
                    .ConfigureAwait(false);
                if (removed)
                {
                    _ = productionStore.TransitionOwnedOperationIntentStatus(
                        intent.Id,
                        executionEpoch,
                        intent.Status,
                        OperationIntentStatus.Reconciled,
                        timeProvider.GetUtcNow());
                }
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                // The unreconciled durable intent remains authoritative.
            }
        }

        var unresolved = productionStore
            .ReadOperationIntents(operationId)
            .Where(
                static intent =>
                    intent.Kind == OperationIntentKind.ChallengeWrite &&
                    intent.Status != OperationIntentStatus.Reconciled)
            .ToArray();
        if (unresolved.Length != 0)
        {
            return new ChallengeCleanupRecovery(
                Verified: false,
                Required: true);
        }

        if (challengeWrites.Length != 0 && !aggregateCleanupVerified)
        {
            await recoveryJournal.AppendAsync(
                    LiveRenewalJournalAction.ChallengeCleanup,
                    LiveRenewalJournalOutcome.Succeeded,
                    "challenge.cleanup_complete",
                    "Restart recovery verifiably removed every persisted HTTP-01 challenge response.",
                    cancellationToken)
                .ConfigureAwait(false);
            aggregateCleanupVerified = true;
        }

        return new ChallengeCleanupRecovery(
            aggregateCleanupVerified,
            Required: false);
    }

    private static bool IsDirectChallengeChild(
        RemotePosixPath path,
        RemotePosixPath challengeWebroot)
    {
        try
        {
            _ = new RemoteTokenSegment(path.FileName.Value);
            return path.Parent == challengeWebroot;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private async Task<bool> AbortAfterRollbackAsync(
        OperationId operationId,
        Guid executionEpoch,
        IRemoteSshSession session,
        RecoveryJournalWriter recoveryJournal,
        CancellationToken cancellationToken)
    {
        var intentRecorded = false;
        try
        {
            await recoveryJournal.AppendAsync(
                    LiveRenewalJournalCategory.Intent,
                    LiveRenewalJournalAction.Abort,
                    LiveRenewalJournalOutcome.Planned,
                    "abort.planned",
                    "Restart recovery will discard the inactive transaction, destroy incoming private-key material, and release the remote generation.",
                    cancellationToken)
                .ConfigureAwait(false);
            intentRecorded = true;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // The fixed Abort call is still required as a safety cleanup, but
            // the recovery result cannot be terminal without durable proof.
        }

        var aborted = await InvokeHelperWithPhaseAsync(
                session,
                RemoteHelperVerbV1.Abort,
                new RemoteTransactionId(operationId.Value),
                cancellationToken)
            .ConfigureAwait(false);
        var evidenceRecorded = false;
        try
        {
            await recoveryJournal.AppendAsync(
                    LiveRenewalJournalAction.Abort,
                    aborted
                        ? LiveRenewalJournalOutcome.Succeeded
                        : LiveRenewalJournalOutcome.Failed,
                    aborted ? "abort.succeeded" : "abort.failed",
                    aborted
                        ? "Restart recovery discarded the inactive transaction, destroyed incoming private-key material, and released the remote generation."
                        : "Restart recovery could not verifiably discard the inactive transaction and its incoming private-key material.",
                    cancellationToken)
                .ConfigureAwait(false);
            evidenceRecorded = true;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // The unreconciled durable intent keeps the operation blocked.
        }

        if (intentRecorded && aborted && evidenceRecorded)
        {
            ReconcileIntentKind(
                operationId,
                executionEpoch,
                OperationIntentKind.Abort);
            return true;
        }

        return false;
    }

    private async Task<LiveRenewalResult> RollbackAfterRecoveryFailureAsync(
        OperationId operationId,
        Guid executionEpoch,
        LiveHttp01RenewalRequest request,
        CertificateArtifact? artifact,
        bool cleanupVerified,
        IRemoteSshSession session,
        RecoveryJournalWriter recoveryJournal,
        string failureCode,
        CancellationToken cancellationToken)
    {
        await recoveryJournal.AppendAsync(
                LiveRenewalJournalCategory.Intent,
                LiveRenewalJournalAction.Rollback,
                LiveRenewalJournalOutcome.Planned,
                "rollback.planned",
                "Restart recovery will restore the prior certificate generation.",
                cancellationToken)
            .ConfigureAwait(false);
        var rolledBack = await InvokeHelperWithPhaseAsync(
                session,
                RemoteHelperVerbV1.Rollback,
                new RemoteTransactionId(operationId.Value),
                cancellationToken)
            .ConfigureAwait(false);
        await recoveryJournal.AppendAsync(
                LiveRenewalJournalAction.Rollback,
                rolledBack
                    ? LiveRenewalJournalOutcome.Succeeded
                    : LiveRenewalJournalOutcome.Failed,
                rolledBack ? "rollback.succeeded" : "rollback.failed",
                rolledBack
                    ? "Restart recovery restored the prior certificate generation."
                    : "Restart recovery could not restore the prior certificate generation.",
                cancellationToken)
            .ConfigureAwait(false);
        if (rolledBack)
        {
            ReconcileIntentKind(
                operationId,
                executionEpoch,
                OperationIntentKind.Rollback);
        }
        var abortVerified = rolledBack &&
            await AbortAfterRollbackAsync(
                    operationId,
                    executionEpoch,
                    session,
                    recoveryJournal,
                    cancellationToken)
                .ConfigureAwait(false);
        return CreateRecoveryResult(
            operationId,
            rolledBack
                ? abortVerified && cleanupVerified
                    ? LiveRenewalStatus.Failed
                    : LiveRenewalStatus.Blocked
                : LiveRenewalStatus.RollbackRequired,
            rolledBack
                ? !abortVerified
                    ? "recovery.abort_required"
                    : cleanupVerified
                        ? failureCode
                        : "recovery.challenge_cleanup_required"
                : "recovery.rollback_failed",
            cleanupVerified,
            publicTlsVerified: false,
            activationAttempted: true,
            rollbackAttempted: true,
            rollbackSucceeded: rolledBack,
            artifact,
            request);
    }

    private async Task<IRemoteSshSession> ConnectAsync(
        LiveHttp01RenewalRequest request,
        CancellationToken cancellationToken)
    {
        byte[]? privateKeyBytes = null;
        try
        {
            privateKeyBytes = secretVault.Read(request.SshPrivateKeyReference);
            using var privateKey = new RemotePrivateKeyMaterial(privateKeyBytes);
            return await remoteSessionFactory
                .ConnectAsync(
                    request.SshConnection,
                    privateKey,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            if (privateKeyBytes is not null)
            {
                CryptographicOperations.ZeroMemory(privateKeyBytes);
            }
        }
    }

    private async Task<bool> VerifyEveryDnsNameAsync(
        LiveHttp01RenewalRequest request,
        CertificateArtifact artifact,
        CancellationToken cancellationToken)
    {
        var verified = 1;
        using var overallPhase = CreateScaledRecoveryPhaseTokenSource(
            request.DnsNames.Count,
            MaximumParallelTlsVerifications,
            cancellationToken);
        try
        {
            await Parallel.ForEachAsync(
                    request.DnsNames,
                    new ParallelOptions
                    {
                        MaxDegreeOfParallelism =
                            MaximumParallelTlsVerifications,
                        CancellationToken = overallPhase.Token,
                    },
                    async (dnsName, phaseCancellationToken) =>
                    {
                        using var probePhase =
                            CancellationTokenSource.CreateLinkedTokenSource(
                                phaseCancellationToken);
                        probePhase.CancelAfter(recoveryPhaseTimeout);
                        var result = await tlsVerifier
                            .VerifyAsync(
                                new PublicTlsVerificationRequest(
                                    dnsName,
                                    request.TlsPort,
                                    artifact.CertificateSha256.Value,
                                    request.TlsTrustPolicy),
                                probePhase.Token)
                            .ConfigureAwait(false);
                        if (!result.Success ||
                            !string.Equals(
                                result.ObservedLeafSha256,
                                artifact.CertificateSha256.Value,
                                StringComparison.OrdinalIgnoreCase))
                        {
                            _ = Interlocked.Exchange(ref verified, 0);
                        }
                    })
                .ConfigureAwait(false);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }

        return Volatile.Read(ref verified) == 1;
    }

    private async Task<bool> InvokeHelperWithPhaseAsync(
        IRemoteSshSession session,
        RemoteHelperVerbV1 verb,
        RemoteTransactionId transactionId,
        CancellationToken cancellationToken)
    {
        using var helperPhase = CreateRecoveryPhaseTokenSource(
            cancellationToken);
        try
        {
            var result = await session
                .InvokeHelperAsync(verb, transactionId, helperPhase.Token)
                .ConfigureAwait(false);
            return result.Succeeded;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    private CancellationTokenSource CreateRecoveryPhaseTokenSource(
        CancellationToken cancellationToken)
    {
        var phase = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        phase.CancelAfter(recoveryPhaseTimeout);
        return phase;
    }

    private CancellationTokenSource CreateScaledRecoveryPhaseTokenSource(
        int itemCount,
        int maximumDegreeOfParallelism,
        CancellationToken cancellationToken)
    {
        var waveCount = Math.Max(
            1,
            (itemCount + maximumDegreeOfParallelism - 1) /
            maximumDegreeOfParallelism);
        var maximumTicks = TimeSpan.FromMinutes(5).Ticks;
        var scaledTicks = recoveryPhaseTimeout.Ticks >
            maximumTicks / waveCount
            ? maximumTicks
            : recoveryPhaseTimeout.Ticks * waveCount;
        var phase = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        phase.CancelAfter(TimeSpan.FromTicks(scaledTicks));
        return phase;
    }

    private void ReconcileIntentKind(
        OperationId operationId,
        Guid executionEpoch,
        OperationIntentKind kind)
    {
        foreach (var intent in productionStore
                     .ReadOperationIntents(operationId)
                     .Where(intent => intent.Kind == kind &&
                         intent.Status != OperationIntentStatus.Reconciled))
        {
            _ = productionStore.TransitionOwnedOperationIntentStatus(
                intent.Id,
                executionEpoch,
                intent.Status,
                OperationIntentStatus.Reconciled,
                timeProvider.GetUtcNow());
        }
    }

    private static LiveRenewalResult CreateRecoveryResult(
        OperationId operationId,
        LiveRenewalStatus status,
        string? failureCode,
        bool cleanupVerified,
        bool publicTlsVerified,
        bool activationAttempted,
        bool rollbackAttempted,
        bool rollbackSucceeded,
        CertificateArtifact? artifact,
        LiveHttp01RenewalRequest request) =>
        new(
            operationId.Value,
            status,
            failureCode,
            cleanupVerified,
            publicTlsVerified,
            activationAttempted,
            rollbackAttempted,
            rollbackSucceeded,
            artifact?.CertificateSha256.Value,
            artifact?.PublicKeySha256.Value,
            artifact?.NotBeforeUtc,
            artifact?.NotAfterUtc,
            artifact is null
                ? null
                : new SecretReference(
                    Guid.ParseExact(
                        artifact.PrivateKeySecretReference,
                        "D")),
            request.TlsTrustPolicy);

    private static HelperStatus ParseHelperStatus(
        string json,
        RemoteTransactionId transactionId)
    {
        HelperStatus? status;
        try
        {
            status = JsonSerializer.Deserialize<HelperStatus>(
                json,
                helperJsonOptions);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "The remote helper returned invalid status JSON.",
                exception);
        }

        if (status is null ||
            status.Version != 1 ||
            !status.Success ||
            status.Code != "helper.status" ||
            status.TransactionId != transactionId.ToString() ||
            status.Status is not (
                "prepared" or
                "validated" or
                "activating" or
                "active" or
                "rolling-back" or
                "rolled-back" or
                "committed" or
                "aborted") ||
            (status.Status is "active" or "committed") && !status.Active ||
            status.Status is (
                "prepared" or "validated" or "rolled-back" or "aborted") &&
                status.Active ||
            (status.Status is "activating" or "rolling-back") !=
                status.RecoveryRequired)
        {
            throw new InvalidDataException(
                "The remote helper returned an unsupported status response.");
        }

        return status;
    }

    private static string? TryReadHelperFailureCode(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty("code", out var code) &&
                code.ValueKind == JsonValueKind.String
                ? code.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static void ValidateOperationRequest(
        OperationId operationId,
        LiveHttp01RenewalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.OperationId != operationId.Value)
        {
            throw new ArgumentException(
                "The renewal request and durable operation identifiers do not match.",
                nameof(request));
        }
    }

    private sealed record HelperStatus(
        int Version,
        bool Success,
        string Code,
        string TransactionId,
        string Status,
        bool Active,
        bool RecoveryRequired);

    private sealed record ChallengeCleanupRecovery(
        bool Verified,
        bool Required);

    private sealed class RecoveryJournalWriter
    {
        private readonly ProductionLiveRenewalJournal journal;
        private readonly OperationId operationId;
        private readonly TimeProvider timeProvider;
        private long sequence;

        public RecoveryJournalWriter(
            ProductionLiveRenewalJournal journal,
            OperationId operationId,
            long sequence,
            TimeProvider timeProvider)
        {
            this.journal = journal;
            this.operationId = operationId;
            this.sequence = sequence;
            this.timeProvider = timeProvider;
        }

        public Task AppendAsync(
            LiveRenewalJournalAction action,
            LiveRenewalJournalOutcome outcome,
            string code,
            string description,
            CancellationToken cancellationToken) =>
            AppendAsync(
                LiveRenewalJournalCategory.Evidence,
                action,
                outcome,
                code,
                description,
                cancellationToken);

        public Task AppendWithSubjectAsync(
            LiveRenewalJournalCategory category,
            LiveRenewalJournalAction action,
            LiveRenewalJournalOutcome outcome,
            string code,
            string description,
            string subject,
            CancellationToken cancellationToken)
        {
            sequence = checked(sequence + 1);
            return journal.AppendAsync(
                new LiveRenewalJournalEntry(
                    operationId.Value,
                    sequence,
                    category,
                    action,
                    outcome,
                    timeProvider.GetUtcNow(),
                    code,
                    description,
                    subject),
                cancellationToken);
        }

        public Task AppendAsync(
            LiveRenewalJournalCategory category,
            LiveRenewalJournalAction action,
            LiveRenewalJournalOutcome outcome,
            string code,
            string description,
            CancellationToken cancellationToken)
        {
            sequence = checked(sequence + 1);
            return journal.AppendAsync(
                new LiveRenewalJournalEntry(
                    operationId.Value,
                    sequence,
                    category,
                    action,
                    outcome,
                    timeProvider.GetUtcNow(),
                    code,
                    description),
                cancellationToken);
        }
    }
}
