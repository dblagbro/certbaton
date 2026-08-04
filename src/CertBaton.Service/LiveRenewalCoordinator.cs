using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using CertBaton.Application.Live;
using CertBaton.Application.Persistence;
using CertBaton.Application.Remote;
using CertBaton.Application.Security;
using CertBaton.Contracts;
using CertBaton.Domain.Operations;
using CertBaton.Domain.Scheduling;
using CertBaton.Domain.Targets;

namespace CertBaton.Service;

public sealed partial class LiveRenewalCoordinator : BackgroundService, ILiveRenewalCoordinator
{
    private const int MaximumActiveOperations = LiveContractValues.MaximumTargets;
    private static readonly TimeSpan ScheduleScanInterval = TimeSpan.FromMinutes(1);
    private readonly IProductionStore store;
    private readonly ILiveRenewalExecutor executor;
    private readonly TimeProvider timeProvider;
    private readonly ILogger<LiveRenewalCoordinator> logger;
    private readonly LiveMaintenanceGate maintenanceGate;
    private readonly Channel<bool> wakeSignal = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1)
        {
            AllowSynchronousContinuations = false,
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
            SingleWriter = false,
        });
    private readonly Guid executionEpoch = Guid.CreateVersion7();

    public LiveRenewalCoordinator(
        IProductionStore store,
        ILiveRenewalExecutor executor,
        TimeProvider timeProvider,
        ILogger<LiveRenewalCoordinator> logger,
        LiveMaintenanceGate? maintenanceGate = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(executor);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);
        this.store = store;
        this.executor = executor;
        this.timeProvider = timeProvider;
        this.logger = logger;
        this.maintenanceGate = maintenanceGate ?? new LiveMaintenanceGate();
    }

    public Task<RenewalOperationSnapshot> StartAsync(
        RenewalStartPayload payload,
        string actorSid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSid);
        cancellationToken.ThrowIfCancellationRequested();
        maintenanceGate.ThrowIfPaused();
        if (!payload.TryValidate(out var validationError))
        {
            throw new ArgumentException(validationError, nameof(payload));
        }

        var targetId = new TargetId(payload.TargetId);
        _ = BuildRequest(OperationId.Create(), targetId);
        var operation = QueueOperation(
            targetId,
            $"manual:{payload.TargetId:N}:{payload.IdempotencyKey:N}",
            GetUtcNow());
        _ = wakeSignal.Writer.TryWrite(true);
        return Task.FromResult(ToSnapshot(operation));
    }

    public RenewalOperationSnapshot? Find(Guid operationId)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "The operation identifier cannot be empty.",
                nameof(operationId));
        }

        var operation = store.FindOperation(new OperationId(operationId));
        return operation is null ? null : ToSnapshot(operation);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await maintenanceGate.WaitUntilOpenAsync(stoppingToken)
                .ConfigureAwait(false);
            await RecoverInterruptedOperationsAsync(stoppingToken)
                .ConfigureAwait(false);
            await maintenanceGate.WaitUntilOpenAsync(stoppingToken)
                .ConfigureAwait(false);
            QueueDueTargets();
            using var scheduleTimer = new PeriodicTimer(
                ScheduleScanInterval,
                timeProvider);
            var wakeTask = wakeSignal.Reader
                .WaitToReadAsync(stoppingToken)
                .AsTask();
            var scheduleTask = scheduleTimer
                .WaitForNextTickAsync(stoppingToken)
                .AsTask();

            while (!stoppingToken.IsCancellationRequested)
            {
                await maintenanceGate.WaitUntilOpenAsync(stoppingToken)
                    .ConfigureAwait(false);
                var processed = await ProcessNextQueuedOperationAsync(stoppingToken)
                    .ConfigureAwait(false);
                if (processed)
                {
                    continue;
                }

                var completed = await Task.WhenAny(wakeTask, scheduleTask)
                    .ConfigureAwait(false);
                if (completed == wakeTask)
                {
                    if (!await wakeTask.ConfigureAwait(false))
                    {
                        break;
                    }

                    while (wakeSignal.Reader.TryRead(out _))
                    {
                    }

                    wakeTask = wakeSignal.Reader
                        .WaitToReadAsync(stoppingToken)
                        .AsTask();
                }
                else
                {
                    if (!await scheduleTask.ConfigureAwait(false))
                    {
                        break;
                    }

                    await RecoverInterruptedOperationsAsync(stoppingToken)
                        .ConfigureAwait(false);
                    await maintenanceGate.WaitUntilOpenAsync(stoppingToken)
                        .ConfigureAwait(false);
                    QueueDueTargets();
                    scheduleTask = scheduleTimer
                        .WaitForNextTickAsync(stoppingToken)
                        .AsTask();
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            wakeSignal.Writer.TryComplete();
        }
    }

    private RenewalOperation QueueOperation(
        TargetId targetId,
        string requestKey,
        DateTimeOffset requestedAtUtc)
    {
        var operation = RenewalOperation.CreateQueued(
            OperationId.Create(),
            targetId,
            requestKey,
            requestedAtUtc);
        return store.CreateOrGetOperation(operation);
    }

    private async Task<bool> ProcessNextQueuedOperationAsync(
        CancellationToken stoppingToken)
    {
        var queued = store
            .ListActiveOperations(MaximumActiveOperations)
            .FirstOrDefault(
                static operation => operation.Status == OperationStatus.Queued);
        if (queued is null)
        {
            return false;
        }

        var claimed = store.TryStartOperation(
            queued.Id,
            executionEpoch,
            GetUtcNow());
        if (claimed is null)
        {
            return true;
        }

        try
        {
            var request = BuildRequest(claimed.Id, claimed.TargetId);
            var result = await executor
                .RunAsync(
                    claimed.Id,
                    executionEpoch,
                    request,
                    stoppingToken)
                .ConfigureAwait(false);
            CompleteFromResult(
                claimed,
                OperationStatus.Running,
                executionEpoch,
                result);
            LogLiveRenewalCompleted(logger, claimed.Id.Value, result.Status);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            CompleteUnexpectedFailure(
                claimed,
                OperationStatus.Interrupted,
                "service.stopping");
        }
        catch (Exception exception)
        {
            LogLiveRenewalFailed(logger, claimed.Id.Value, exception);
            CompleteUnexpectedFailure(
                claimed,
                OperationStatus.Failed,
                "service.execution_failed");
        }

        return true;
    }

    private void CompleteFromResult(
        RenewalOperation claimed,
        OperationStatus expectedStatus,
        Guid ownerEpoch,
        LiveRenewalResult result)
    {
        if (result.OperationId != claimed.Id.Value)
        {
            throw new InvalidOperationException(
                "The renewal executor returned a result for another operation.");
        }

        var now = GetUtcNow();
        switch (result.Status)
        {
            case LiveRenewalStatus.Succeeded:
                {
                    var artifact = store.FindCertificateArtifact(claimed.Id)
                        ?? throw new InvalidOperationException(
                            "A successful renewal did not persist its issued certificate artifact.");
                    if (!string.Equals(
                            artifact.CertificateSha256.Value,
                            result.CertificateLeafSha256,
                            StringComparison.Ordinal) ||
                        !string.Equals(
                            artifact.PublicKeySha256.Value,
                            result.PublicKeySha256,
                            StringComparison.Ordinal) ||
                        artifact.NotBeforeUtc != result.NotBeforeUtc ||
                        artifact.NotAfterUtc != result.NotAfterUtc ||
                        !string.Equals(
                            artifact.PrivateKeySecretReference,
                            result.CertificatePrivateKeyReference?.ToString(),
                            StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(
                            "The persisted certificate artifact does not match the verified renewal result.");
                    }

                    _ = store.CompleteOwnedLiveRenewal(
                        claimed.Id,
                        ownerEpoch,
                        expectedStatus,
                        OperationStatus.Succeeded,
                        now,
                        CalculateNextDueAt(
                            claimed.TargetId,
                            succeeded: true,
                            claimed.Id,
                            now));
                    break;
                }

            case LiveRenewalStatus.Failed:
                _ = store.CompleteOwnedLiveRenewal(
                    claimed.Id,
                    ownerEpoch,
                    expectedStatus,
                    OperationStatus.Failed,
                    now,
                    CalculateNextDueAt(
                        claimed.TargetId,
                        succeeded: false,
                        operationId: null,
                        now),
                    result.FailureCode);
                break;

            case LiveRenewalStatus.Cancelled:
                _ = store.CompleteOwnedLiveRenewal(
                    claimed.Id,
                    ownerEpoch,
                    expectedStatus,
                    OperationStatus.Cancelled,
                    now,
                    CalculateNextDueAt(
                        claimed.TargetId,
                        succeeded: false,
                        operationId: null,
                        now),
                    result.FailureCode);
                break;

            case LiveRenewalStatus.RollbackRequired:
                _ = store.TransitionOwnedOperationStatus(
                    claimed.Id,
                    ownerEpoch,
                    expectedStatus,
                    OperationStatus.RollbackRequired,
                    now,
                    result.FailureCode);
                break;

            case LiveRenewalStatus.Blocked:
                _ = store.TransitionOwnedOperationStatus(
                    claimed.Id,
                    ownerEpoch,
                    expectedStatus,
                    OperationStatus.Blocked,
                    now,
                    result.FailureCode);
                break;

            default:
                throw new InvalidOperationException(
                    "The renewal executor returned an unsupported status.");
        }
    }

    private void CompleteUnexpectedFailure(
        RenewalOperation claimed,
        OperationStatus terminalStatus,
        string failureCode)
    {
        try
        {
            var current = store.FindOperation(claimed.Id);
            if (current is null || RenewalOperation.IsTerminal(current.Status))
            {
                return;
            }

            var intents = store.ReadOperationIntents(claimed.Id);
            var activationMayHaveStarted = intents
                .Any(
                    static intent =>
                        intent.Kind == OperationIntentKind.Activate &&
                        intent.Status is OperationIntentStatus.Planned or
                            OperationIntentStatus.Applied or
                            OperationIntentStatus.Uncertain);
            if (activationMayHaveStarted)
            {
                var recoveryRecordedAt = GetUtcNow();
                _ = store.AppendOperationEvidence(
                    claimed.Id,
                    OperationEvidenceKind.Recovery,
                    stage: null,
                    OperationEvidenceOutcome.Failed,
                    recoveryRecordedAt,
                    "service.execution_recovery_required",
                    "Execution stopped after activation became possible; explicit remote recovery is required.");
                _ = store.TransitionOwnedOperationStatus(
                    claimed.Id,
                    executionEpoch,
                    current.Status,
                    OperationStatus.RollbackRequired,
                    recoveryRecordedAt,
                    "service.execution_recovery_required");
                return;
            }

            var challengeCleanupRequired = intents.Any(
                static intent =>
                    intent.Kind == OperationIntentKind.ChallengeWrite &&
                    intent.Status != OperationIntentStatus.Reconciled);
            var remotePrepareMayExist = intents.Any(
                static intent =>
                    intent.Kind == OperationIntentKind.RemotePrepare &&
                    intent.Status is OperationIntentStatus.Planned or
                        OperationIntentStatus.Applied or
                        OperationIntentStatus.Uncertain or
                        OperationIntentStatus.Failed);
            var abortVerified = intents.Any(
                static intent =>
                    intent.Kind == OperationIntentKind.Abort &&
                    intent.Status is OperationIntentStatus.Applied or
                        OperationIntentStatus.Reconciled);
            if (challengeCleanupRequired ||
                (remotePrepareMayExist && !abortVerified))
            {
                var recoveryRecordedAt = GetUtcNow();
                _ = store.AppendOperationEvidence(
                    claimed.Id,
                    OperationEvidenceKind.Recovery,
                    stage: null,
                    OperationEvidenceOutcome.Failed,
                    recoveryRecordedAt,
                    "service.cleanup_recovery_required",
                    "Execution stopped with unresolved pre-activation remote cleanup; automatic recovery will retry.");
                _ = store.TransitionOwnedOperationStatus(
                    claimed.Id,
                    executionEpoch,
                    current.Status,
                    OperationStatus.Blocked,
                    recoveryRecordedAt,
                    "service.cleanup_recovery_required");
                return;
            }

            var completedAt = GetUtcNow();
            _ = store.AppendOperationEvidence(
                claimed.Id,
                OperationEvidenceKind.Terminal,
                stage: null,
                terminalStatus == OperationStatus.Cancelled
                    ? OperationEvidenceOutcome.Cancelled
                    : OperationEvidenceOutcome.Failed,
                completedAt,
                failureCode,
                "The service stopped the renewal after an internal execution failure.");
            _ = store.CompleteOwnedLiveRenewal(
                claimed.Id,
                executionEpoch,
                current.Status,
                terminalStatus,
                completedAt,
                CalculateNextDueAt(
                    claimed.TargetId,
                    succeeded: false,
                    operationId: null,
                    completedAt),
                failureCode);
        }
        catch (Exception exception)
        {
            LogLiveRenewalPersistenceFailed(
                logger,
                claimed.Id.Value,
                exception);
        }
    }

    private LiveHttp01RenewalRequest BuildRequest(
        OperationId operationId,
        TargetId targetId)
    {
        var target = store.FindTarget(targetId)
            ?? throw new KeyNotFoundException(
                "The selected certificate target does not exist.");
        if (target.LifecycleStatus != TargetLifecycleStatus.Ready)
        {
            throw new InvalidOperationException(
                "The selected certificate target is not ready for live renewal.");
        }

        var connection = store.FindConnection(target.ConnectionId)
            ?? throw new InvalidOperationException(
                "The selected target has no SSH connection profile.");
        var deployment = store.FindEnabledDeploymentPlan(targetId)
            ?? throw new InvalidOperationException(
                "The selected target has no enabled deployment plan.");
        var issuance = store.FindTargetIssuanceProfile(targetId)
            ?? throw new InvalidOperationException(
                "The selected target has no ACME issuance profile.");
        if (!connection.Enabled ||
            connection.HostKeyAlgorithm is null ||
            !connection.HasRawHostKey ||
            !deployment.Enabled ||
            !deployment.RemoteIncomingRoot.HasValue ||
            !issuance.TermsAccepted)
        {
            throw new InvalidOperationException(
                "The selected target is not fully enrolled for live renewal.");
        }

        if (!Guid.TryParseExact(
                connection.CredentialReference,
                "D",
                out var credentialReference) ||
            !Guid.TryParseExact(
                issuance.AccountKeySecretReference,
                "D",
                out var accountKeyReference))
        {
            throw new InvalidOperationException(
                "The selected target contains an invalid secret reference.");
        }

        var endpoint = RemoteSshEndpoint.Create(
            connection.Endpoint.Host,
            connection.Endpoint.Port,
            connection.Username);
        var rawHostKey = connection.ExportRawHostKey()
            ?? throw new InvalidOperationException(
                "The selected target has no exact SSH host-key pin.");
        try
        {
            var pin = SshHostKeyPin.Create(
                endpoint.Host,
                endpoint.Port,
                connection.HostKeyAlgorithm,
                connection.HostKeyFingerprint,
                rawHostKey);
            return new LiveHttp01RenewalRequest(
                operationId.Value,
                target.Names.Select(static name => name.Value),
                issuance.DirectoryUri,
                [issuance.Contact.Value],
                issuance.TermsAccepted,
                ResolveTrustMode(issuance.DirectoryUri),
                new SecretReference(accountKeyReference),
                new RemoteSshConnectionOptions(endpoint, pin),
                new SecretReference(credentialReference),
                RemotePosixPath.Parse(deployment.ChallengeWebroot.Value),
                RemotePosixPath.Parse(
                    deployment.RemoteIncomingRoot.Value.Value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawHostKey);
        }
    }

    private static AcmeCertificateTrustMode ResolveTrustMode(Uri directoryUri) =>
        directoryUri.AbsoluteUri switch
        {
            LiveContractValues.LetsEncryptStagingDirectory =>
                AcmeCertificateTrustMode.UntrustedTest,
            LiveContractValues.LetsEncryptProductionDirectory =>
                AcmeCertificateTrustMode.PubliclyTrusted,
            _ => throw new InvalidOperationException(
                "The selected target uses an unsupported ACME directory."),
        };

    private async Task RecoverInterruptedOperationsAsync(
        CancellationToken cancellationToken)
    {
        foreach (var operation in store.ListActiveOperations(MaximumActiveOperations))
        {
            if (operation.Status == OperationStatus.Queued)
            {
                continue;
            }

            if (!operation.ExecutionEpoch.HasValue)
            {
                throw new InvalidOperationException(
                    "An active persisted operation has no execution owner.");
            }

            try
            {
                var request = BuildRequest(operation.Id, operation.TargetId);
                var result = await executor
                    .RecoverAsync(
                        operation.Id,
                        operation.ExecutionEpoch.Value,
                        request,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (result.Status == LiveRenewalStatus.Failed &&
                    !result.ActivationAttempted)
                {
                    var completedAt = GetUtcNow();
                    _ = store.CompleteOwnedLiveRenewal(
                        operation.Id,
                        operation.ExecutionEpoch.Value,
                        operation.Status,
                        OperationStatus.Interrupted,
                        completedAt,
                        CalculateNextDueAt(
                            operation.TargetId,
                            succeeded: false,
                            operationId: null,
                            completedAt),
                        result.FailureCode ?? "service.restart_interrupted");
                }
                else
                {
                    CompleteFromResult(
                        operation,
                        operation.Status,
                        operation.ExecutionEpoch.Value,
                        result);
                }

                LogLiveRenewalRecovered(
                    logger,
                    operation.Id.Value,
                    result.Status);
            }
            catch (OperationCanceledException) when (
                cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                LogLiveRenewalRecoveryFailed(
                    logger,
                    operation.Id.Value,
                    exception);
                MarkRecoveryRequired(operation);
            }
        }
    }

    private void MarkRecoveryRequired(RenewalOperation operation)
    {
        if (!operation.ExecutionEpoch.HasValue ||
            RenewalOperation.IsTerminal(operation.Status))
        {
            return;
        }

        var intents = store.ReadOperationIntents(operation.Id);
        var activationMayHaveStarted = intents.Any(
            static intent =>
                intent.Kind == OperationIntentKind.Activate &&
                intent.Status is OperationIntentStatus.Planned or
                    OperationIntentStatus.Applied or
                    OperationIntentStatus.Uncertain);
        var blockedStatus = activationMayHaveStarted
            ? OperationStatus.RollbackRequired
            : OperationStatus.Blocked;
        if (operation.Status == blockedStatus &&
            operation.FailureCode == "service.restart_recovery_required")
        {
            return;
        }

        var now = GetUtcNow();
        _ = store.AppendOperationEvidence(
            operation.Id,
            OperationEvidenceKind.Recovery,
            stage: null,
            OperationEvidenceOutcome.Failed,
            now,
            "service.restart_recovery_required",
            activationMayHaveStarted
                ? "The service could not prove the post-activation remote state; rollback recovery will retry."
                : "The service could not prove pre-activation cleanup; automatic cleanup recovery will retry.");
        _ = store.TransitionOwnedOperationStatus(
            operation.Id,
            operation.ExecutionEpoch.Value,
            operation.Status,
            blockedStatus,
            now,
            "service.restart_recovery_required");
    }

    private void QueueDueTargets()
    {
        var now = GetUtcNow();
        foreach (var target in store.ListTargets(LiveContractValues.MaximumTargets))
        {
            var policy = store.FindEnabledRenewalPolicy(target.Id);
            if (policy?.Enabled != true ||
                policy.NextDueAtUtc is null ||
                policy.NextDueAtUtc > now ||
                target.LifecycleStatus != TargetLifecycleStatus.Ready)
            {
                continue;
            }

            try
            {
                _ = BuildRequest(OperationId.Create(), target.Id);
                var operation = QueueOperation(
                    target.Id,
                    CreateAutomaticRequestKey(
                        target.Id,
                        policy.NextDueAtUtc.Value,
                        now,
                        policy.CheckIntervalMinutes),
                    now);
                if (RenewalOperation.IsTerminal(operation.Status))
                {
                    Reschedule(
                        target.Id,
                        operation.Status == OperationStatus.Succeeded,
                        operation.Id);
                }
                else
                {
                    _ = wakeSignal.Writer.TryWrite(true);
                }
            }
            catch (ProductionOperationAlreadyActiveException)
            {
            }
            catch (Exception exception)
            {
                LogAutomaticRenewalQueueFailed(
                    logger,
                    target.Id.Value,
                    exception);
                TryRescheduleAfterQueueFailure(target.Id);
            }
        }
    }

    private void TryRescheduleAfterQueueFailure(TargetId targetId)
    {
        try
        {
            Reschedule(targetId, succeeded: false);
        }
        catch (Exception exception)
        {
            LogAutomaticRenewalQueueFailed(
                logger,
                targetId.Value,
                exception);
        }
    }

    private void Reschedule(
        TargetId targetId,
        bool succeeded,
        OperationId? operationId = null)
    {
        var policy = store.FindEnabledRenewalPolicy(targetId);
        if (policy?.Enabled != true)
        {
            return;
        }

        var now = GetUtcNow();
        var nextDue = CalculateNextDueAt(
            targetId,
            succeeded,
            operationId,
            now);

        store.SaveRenewalPolicy(
            new RenewalPolicy(
                policy.Id,
                policy.TargetId,
                policy.RenewBeforeDays,
                policy.CheckIntervalMinutes,
                policy.Enabled,
                nextDue,
                policy.CreatedAtUtc,
                now));
    }

    private DateTimeOffset CalculateNextDueAt(
        TargetId targetId,
        bool succeeded,
        OperationId? operationId,
        DateTimeOffset nowUtc)
    {
        var policy = store.FindRenewalPolicyByTarget(targetId)
            ?? throw new InvalidOperationException(
                "The renewal target has no scheduling policy.");
        var retryAt = nowUtc.AddMinutes(policy.CheckIntervalMinutes);
        if (!succeeded)
        {
            return retryAt;
        }

        if (!operationId.HasValue)
        {
            throw new InvalidOperationException(
                "A successful renewal schedule requires its certificate artifact.");
        }

        var artifact = store.FindCertificateArtifact(operationId.Value)
            ?? throw new InvalidOperationException(
                "A successful renewal schedule has no certificate artifact.");
        var observedLifetime = artifact.NotAfterUtc - artifact.NotBeforeUtc;
        var maximumRenewBefore = TimeSpan.FromTicks(observedLifetime.Ticks / 3);
        var configuredRenewBefore = TimeSpan.FromDays(policy.RenewBeforeDays);
        var effectiveRenewBefore = configuredRenewBefore <= maximumRenewBefore
            ? configuredRenewBefore
            : maximumRenewBefore;
        var renewalAt = artifact.NotAfterUtc - effectiveRenewBefore;
        return renewalAt > nowUtc ? renewalAt : retryAt;
    }

    private RenewalOperationSnapshot ToSnapshot(RenewalOperation operation)
    {
        var evidence = store
            .ReadOperationEvidence(operation.Id)
            .TakeLast(LiveContractValues.MaximumEvidenceRecords)
            .Select(ToSnapshot)
            .ToArray();
        var artifact = store.FindCertificateArtifact(operation.Id);
        return new RenewalOperationSnapshot(
            operation.Id.Value,
            operation.TargetId.Value,
            ToContractStatus(operation.Status),
            operation.RequestedAtUtc,
            operation.UpdatedAtUtc,
            operation.CompletedAtUtc,
            operation.FailureCode,
            artifact?.CertificateSha256.Value,
            evidence.Any(
                static item =>
                    item.Code == "tls.all_names_verified" &&
                    item.Outcome == "succeeded"),
            evidence.Any(
                static item =>
                    item.Code == "challenge.cleanup_complete" &&
                    item.Outcome == "succeeded"),
            evidence);
    }

    private static RenewalEvidenceSnapshot ToSnapshot(OperationEvidence evidence) =>
        new(
            evidence.Sequence,
            evidence.Kind.ToString().ToLowerInvariant(),
            evidence.Stage ?? evidence.Kind.ToString().ToLowerInvariant(),
            evidence.Outcome.ToString().ToLowerInvariant(),
            evidence.RecordedAtUtc,
            evidence.Code,
            evidence.Description);

    private static string ToContractStatus(OperationStatus status) => status switch
    {
        OperationStatus.Queued => "queued",
        OperationStatus.Running => "running",
        OperationStatus.Blocked => "blocked",
        OperationStatus.RollbackRequired => "rollback-required",
        OperationStatus.Succeeded => "succeeded",
        OperationStatus.Failed => "failed",
        OperationStatus.Cancelled => "cancelled",
        OperationStatus.Interrupted => "interrupted",
        _ => throw new InvalidOperationException(
            "The persisted operation has an unsupported status."),
    };

    private static string CreateAutomaticRequestKey(
        TargetId targetId,
        DateTimeOffset dueAtUtc,
        DateTimeOffset attemptedAtUtc,
        int checkIntervalMinutes)
    {
        var attemptIntervalMilliseconds = checked(
            (long)checkIntervalMinutes * 60 * 1_000);
        var attemptBucket =
            attemptedAtUtc.ToUnixTimeMilliseconds() /
            attemptIntervalMilliseconds;
        var source = Encoding.UTF8.GetBytes(
            string.Create(
                CultureInfo.InvariantCulture,
                $"automatic:{targetId.Value:N}:{dueAtUtc.ToUnixTimeMilliseconds()}:{attemptBucket}"));
        var digest = SHA256.HashData(source);
        return $"automatic:{targetId.Value:N}:{Convert.ToHexStringLower(digest.AsSpan(0, 16))}";
    }

    private DateTimeOffset GetUtcNow() =>
        timeProvider.GetUtcNow().ToUniversalTime();

    [LoggerMessage(
        EventId = 1200,
        Level = LogLevel.Information,
        Message = "Live renewal {OperationId} completed with status {Status}.")]
    private static partial void LogLiveRenewalCompleted(
        ILogger logger,
        Guid operationId,
        LiveRenewalStatus status);

    [LoggerMessage(
        EventId = 1201,
        Level = LogLevel.Error,
        Message = "Live renewal {OperationId} stopped because its service-owned execution failed.")]
    private static partial void LogLiveRenewalFailed(
        ILogger logger,
        Guid operationId,
        Exception exception);

    [LoggerMessage(
        EventId = 1202,
        Level = LogLevel.Error,
        Message = "Live renewal {OperationId} could not persist its terminal failure state.")]
    private static partial void LogLiveRenewalPersistenceFailed(
        ILogger logger,
        Guid operationId,
        Exception exception);

    [LoggerMessage(
        EventId = 1203,
        Level = LogLevel.Error,
        Message = "Automatic renewal for target {TargetId} could not be queued.")]
    private static partial void LogAutomaticRenewalQueueFailed(
        ILogger logger,
        Guid targetId,
        Exception exception);

    [LoggerMessage(
        EventId = 1204,
        Level = LogLevel.Information,
        Message = "Live renewal {OperationId} recovery completed with status {Status}.")]
    private static partial void LogLiveRenewalRecovered(
        ILogger logger,
        Guid operationId,
        LiveRenewalStatus status);

    [LoggerMessage(
        EventId = 1205,
        Level = LogLevel.Error,
        Message = "Live renewal {OperationId} recovery could not prove a safe remote state.")]
    private static partial void LogLiveRenewalRecoveryFailed(
        ILogger logger,
        Guid operationId,
        Exception exception);
}
