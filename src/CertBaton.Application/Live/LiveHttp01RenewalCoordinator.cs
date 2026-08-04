using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CertBaton.Application.Acme;
using CertBaton.Application.Remote;
using CertBaton.Application.Security;
using CertBaton.Application.Verification;

namespace CertBaton.Application.Live;

public sealed class LiveHttp01RenewalCoordinator
{
    private const int MaximumParallelCleanupOperations = 8;
    private const int MaximumParallelTlsVerifications = 8;
    private static readonly JsonSerializerOptions helperJsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };
    private static readonly RemotePathSegment FullChainFileName =
        new("fullchain.pem");
    private static readonly RemotePathSegment PrivateKeyFileName =
        new("privkey.pem");
    private readonly IAcmeEngine acmeEngine;
    private readonly IAcmeAccountStore accountStore;
    private readonly ICertificatePrivateKeyStore certificatePrivateKeyStore;
    private readonly IIssuedCertificateStore issuedCertificateStore;
    private readonly IRemoteSshSessionFactory remoteSessionFactory;
    private readonly ISecretVault secretVault;
    private readonly IPublicHttp01Verifier http01Verifier;
    private readonly IPublicTlsVerifier tlsVerifier;
    private readonly ICertificateMaterialInspector certificateInspector;
    private readonly ILiveRenewalJournal journal;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan recoveryTimeout;

    public LiveHttp01RenewalCoordinator(
        IAcmeEngine acmeEngine,
        IAcmeAccountStore accountStore,
        ICertificatePrivateKeyStore certificatePrivateKeyStore,
        IIssuedCertificateStore issuedCertificateStore,
        IRemoteSshSessionFactory remoteSessionFactory,
        ISecretVault secretVault,
        IPublicHttp01Verifier http01Verifier,
        IPublicTlsVerifier tlsVerifier,
        ICertificateMaterialInspector certificateInspector,
        ILiveRenewalJournal journal,
        TimeProvider? timeProvider = null,
        TimeSpan? recoveryTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(acmeEngine);
        ArgumentNullException.ThrowIfNull(accountStore);
        ArgumentNullException.ThrowIfNull(certificatePrivateKeyStore);
        ArgumentNullException.ThrowIfNull(issuedCertificateStore);
        ArgumentNullException.ThrowIfNull(remoteSessionFactory);
        ArgumentNullException.ThrowIfNull(secretVault);
        ArgumentNullException.ThrowIfNull(http01Verifier);
        ArgumentNullException.ThrowIfNull(tlsVerifier);
        ArgumentNullException.ThrowIfNull(certificateInspector);
        ArgumentNullException.ThrowIfNull(journal);

        var normalizedRecoveryTimeout =
            recoveryTimeout ?? TimeSpan.FromSeconds(30);
        if (normalizedRecoveryTimeout < TimeSpan.FromSeconds(1) ||
            normalizedRecoveryTimeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(
                nameof(recoveryTimeout),
                normalizedRecoveryTimeout,
                "The recovery timeout must be between one second and five minutes.");
        }

        this.acmeEngine = acmeEngine;
        this.accountStore = accountStore;
        this.certificatePrivateKeyStore = certificatePrivateKeyStore;
        this.issuedCertificateStore = issuedCertificateStore;
        this.remoteSessionFactory = remoteSessionFactory;
        this.secretVault = secretVault;
        this.http01Verifier = http01Verifier;
        this.tlsVerifier = tlsVerifier;
        this.certificateInspector = certificateInspector;
        this.journal = journal;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.recoveryTimeout = normalizedRecoveryTimeout;
    }

    public async Task<LiveRenewalResult> RunAsync(
        LiveHttp01RenewalRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var state = new WorkflowState(request);
        AcmeAccount? storedAccount = null;
        AcmeAccount? activeAccount = null;
        IRemoteSshSession? remoteSession = null;
        LiveCertificateRequest? certificateRequest = null;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            state.PendingFailureCode = "ssh.credential_unavailable";
            if (!secretVault.Contains(request.SshPrivateKeyReference))
            {
                throw new WorkflowFailureException(
                    "ssh.credential_unavailable");
            }

            remoteSession = await ConnectAsync(request, cancellationToken)
                .ConfigureAwait(false);

            state.PendingFailureCode = "account.load_failed";
            storedAccount = await accountStore
                .LoadAsync(
                    request.AcmeDirectoryUri,
                    request.AcmeAccountKeyReference,
                    cancellationToken)
                .ConfigureAwait(false);
            if (storedAccount is not null &&
                storedAccount.DirectoryUri != request.AcmeDirectoryUri)
            {
                throw new WorkflowFailureException(
                    "account.directory_mismatch");
            }

            state.PendingFailureCode = "account.ensure_failed";
            var accountResult = await acmeEngine
                .EnsureAccountAsync(
                    new AcmeAccountRequest(
                        request.AcmeDirectoryUri,
                        request.ContactUris,
                        request.TermsOfServiceAgreed,
                        storedAccount),
                    cancellationToken)
                .ConfigureAwait(false);
            activeAccount = accountResult.Account;
            if (!ReferenceEquals(storedAccount, activeAccount))
            {
                storedAccount?.Dispose();
                storedAccount = null;
            }

            if (accountResult.Status != AcmeResourceStatus.Valid)
            {
                throw new WorkflowFailureException(
                    "account.not_valid");
            }

            state.PendingFailureCode = "account.persist_failed";
            await accountStore.SaveAsync(
                    activeAccount,
                    request.AcmeAccountKeyReference,
                    cancellationToken)
                .ConfigureAwait(false);
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.Account,
                    LiveRenewalJournalOutcome.Succeeded,
                    "account.ready",
                    accountResult.Created
                        ? "The ACME account was created and durably protected."
                        : "The durable ACME account was reused.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);

            state.PendingFailureCode = "order.create_failed";
            var order = await acmeEngine
                .CreateOrderAsync(
                    activeAccount,
                    new AcmeOrderRequest(request.DnsNames),
                    cancellationToken)
                .ConfigureAwait(false);
            ValidateOrder(order, request.DnsNames, "order.identifiers_mismatch");
            if (order.Status == AcmeResourceStatus.Invalid)
            {
                throw new WorkflowFailureException("order.invalid");
            }

            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.Order,
                    LiveRenewalJournalOutcome.Succeeded,
                    "order.created",
                    "The ACME order contains every requested DNS identifier.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);

            state.PendingFailureCode = "challenge.load_failed";
            var challenges = await acmeEngine
                .GetHttp01ChallengesAsync(
                    activeAccount,
                    order.OrderUri,
                    cancellationToken)
                .ConfigureAwait(false);
            var validatedChallenges = ValidateChallenges(
                challenges,
                request.DnsNames);

            try
            {
                foreach (var challenge in validatedChallenges)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await PublishAndValidateChallengeAsync(
                            request,
                            state,
                            activeAccount,
                            remoteSession,
                            challenge,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            finally
            {
                await CleanupChallengesAsync(state, remoteSession)
                    .ConfigureAwait(false);
            }

            if (!state.ChallengeCleanupVerified)
            {
                throw new WorkflowFailureException(
                    "challenge.cleanup_failed");
            }

            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.ChallengeCleanup,
                    LiveRenewalJournalOutcome.Succeeded,
                    "challenge.cleanup_complete",
                    "Every temporary HTTP-01 challenge response was verifiably removed.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();
            certificateRequest = LiveCertificateRequest.Create(
                request.DnsNames);
            state.PendingFailureCode = "certificate_key.persist_failed";
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Intent,
                    LiveRenewalJournalAction.CertificateKeyPersistence,
                    LiveRenewalJournalOutcome.Planned,
                    "certificate_key.persist_planned",
                    "A pending certificate key will be durably protected before finalization.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
            state.CertificatePrivateKeyReference =
                await certificatePrivateKeyStore
                    .StorePendingAsync(
                        request.OperationId,
                        certificateRequest.PrivateKeyPem,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (state.CertificatePrivateKeyReference.Value.Value == Guid.Empty)
            {
                throw new WorkflowFailureException(
                    "certificate_key.reference_invalid");
            }

            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.CertificateKeyPersistence,
                    LiveRenewalJournalOutcome.Applied,
                    "certificate_key.persisted",
                    "The pending certificate key was durably protected.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);

            state.PendingFailureCode = "order.finalize_failed";
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Intent,
                    LiveRenewalJournalAction.CertificateFinalization,
                    LiveRenewalJournalOutcome.Planned,
                    "order.finalize_planned",
                    "The ACME order will be finalized with the protected certificate key.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
            _ = await acmeEngine
                .FinalizeOrderAsync(
                    activeAccount,
                    order.OrderUri,
                    certificateRequest.CertificateSigningRequestDer,
                    cancellationToken)
                .ConfigureAwait(false);
            var orderPoll = await acmeEngine
                .PollOrderAsync(
                    activeAccount,
                    order.OrderUri,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            ValidateOrder(
                orderPoll.Order,
                request.DnsNames,
                "order.identifiers_mismatch");
            if (orderPoll.TimedOut ||
                orderPoll.Order.Status != AcmeResourceStatus.Valid)
            {
                throw new WorkflowFailureException(
                    orderPoll.TimedOut
                        ? "order.poll_timeout"
                        : "order.not_valid");
            }

            var certificateChain = await acmeEngine
                .DownloadCertificateAsync(
                    activeAccount,
                    order.OrderUri,
                    request.PreferredChain,
                    cancellationToken)
                .ConfigureAwait(false);
            ValidateCertificateChain(
                certificateChain,
                request.SshConnection.MaximumTransferBytes);
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.CertificateFinalization,
                    LiveRenewalJournalOutcome.Succeeded,
                    "order.finalized",
                    "The ACME order reached the valid state and returned a certificate chain.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);

            state.PendingFailureCode = "certificate.inspection_failed";
            var inspection = certificateInspector.Inspect(
                certificateChain.LeafCertificatePem,
                certificateRequest.ExportPrivateKeyPemString(),
                request.PrimaryDnsName,
                timeProvider.GetUtcNow());
            if (!inspection.Success ||
                string.IsNullOrWhiteSpace(inspection.LeafSha256))
            {
                throw new WorkflowFailureException(
                    SafeCode(
                        inspection.Code,
                        "certificate.inspection_failed"));
            }

            state.CertificateLeafSha256 = NormalizeSha256(
                inspection.LeafSha256,
                "certificate.fingerprint_invalid");
            var certificateIdentity = InspectCertificateIdentity(
                certificateChain.LeafCertificatePem,
                request.DnsNames);
            if (!string.Equals(
                    certificateIdentity.CertificateLeafSha256,
                    state.CertificateLeafSha256,
                    StringComparison.Ordinal))
            {
                throw new WorkflowFailureException(
                    "certificate.fingerprint_mismatch");
            }

            state.PublicKeySha256 = certificateIdentity.PublicKeySha256;
            state.NotBeforeUtc = certificateIdentity.NotBeforeUtc;
            state.NotAfterUtc = certificateIdentity.NotAfterUtc;
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.CertificateInspection,
                    LiveRenewalJournalOutcome.Succeeded,
                    "certificate.inspected",
                    "The certificate, private key, validity, server use, and primary DNS name were inspected locally.",
                    request.PrimaryDnsName,
                    cancellationToken)
                .ConfigureAwait(false);

            state.PendingFailureCode = "certificate_artifact.persist_failed";
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Intent,
                    LiveRenewalJournalAction.CertificateArtifactPersistence,
                    LiveRenewalJournalOutcome.Planned,
                    "certificate_artifact.persist_planned",
                    "The issued certificate metadata will be durably recorded before remote deployment.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
            await issuedCertificateStore.PersistIssuedAsync(
                    new LiveIssuedCertificateArtifact(
                        request.OperationId,
                        state.CertificateLeafSha256,
                        state.PublicKeySha256,
                        state.CertificatePrivateKeyReference.Value,
                        state.NotBeforeUtc.Value,
                        state.NotAfterUtc.Value),
                    cancellationToken)
                .ConfigureAwait(false);
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.CertificateArtifactPersistence,
                    LiveRenewalJournalOutcome.Applied,
                    "certificate_artifact.persisted",
                    "The issued certificate metadata was durably recorded.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);

            var transactionId = new RemoteTransactionId(request.OperationId);
            state.PendingFailureCode = "remote.prepare_failed";
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Intent,
                    LiveRenewalJournalAction.RemotePrepare,
                    LiveRenewalJournalOutcome.Planned,
                    "remote.prepare_planned",
                    "The remote immutable deployment transaction will be prepared.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
            state.RemotePrepareAttempted = true;
            await InvokePrepareAsync(
                    remoteSession,
                    transactionId,
                    request.IncomingRoot,
                    cancellationToken)
                .ConfigureAwait(false);
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.RemotePrepare,
                    LiveRenewalJournalOutcome.Applied,
                    "remote.prepared",
                    "The remote immutable deployment transaction was prepared.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);

            var transactionDirectory = request.IncomingRoot.Combine(
                new RemotePathSegment(transactionId.ToString()));
            var fullChainPath = transactionDirectory.Combine(
                FullChainFileName);
            var privateKeyPath = transactionDirectory.Combine(
                PrivateKeyFileName);

            state.PendingFailureCode = "deployment.upload_failed";
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Intent,
                    LiveRenewalJournalAction.CertificateDeployment,
                    LiveRenewalJournalOutcome.Planned,
                    "deployment.upload_planned",
                    "The certificate chain and protected private key will be uploaded to the prepared transaction.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
            var fullChainBytes = Encoding.UTF8.GetBytes(
                certificateChain.FullChainPem);
            try
            {
                await using (var fullChainStream = new MemoryStream(
                                 fullChainBytes,
                                 writable: false))
                {
                    await remoteSession.UploadFileAsync(
                            fullChainPath,
                            fullChainStream,
                            RemoteWriteMode.CreateNew,
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                await using var privateKeyStream =
                    certificateRequest.OpenPrivateKeyPemStream();
                await remoteSession.UploadFileAsync(
                        privateKeyPath,
                        privateKeyStream,
                        RemoteWriteMode.CreateNew,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(fullChainBytes);
            }

            await InvokeRequiredHelperAsync(
                    remoteSession,
                    RemoteHelperVerbV1.Validate,
                    transactionId,
                    "deployment.validation_failed",
                    cancellationToken)
                .ConfigureAwait(false);
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.CertificateDeployment,
                    LiveRenewalJournalOutcome.Applied,
                    "deployment.validated",
                    "The remote helper validated the immutable certificate generation and web-server configuration.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);

            // This is the cancellation boundary. Once the durable activation
            // intent exists, recovery-critical work uses its own bounded token.
            cancellationToken.ThrowIfCancellationRequested();
            state.PendingFailureCode = "activation.intent_failed";
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Intent,
                    LiveRenewalJournalAction.Activation,
                    LiveRenewalJournalOutcome.Planned,
                    "activation.planned",
                    "The validated immutable certificate generation will be activated.",
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
            state.ActivationAttempted = true;

            using (var activationPhase = CreateRecoveryTokenSource())
            {
                state.PendingFailureCode = "activation.failed";
                await InvokeRequiredHelperAsync(
                        remoteSession,
                        RemoteHelperVerbV1.Activate,
                        transactionId,
                        "activation.failed",
                        activationPhase.Token)
                    .ConfigureAwait(false);
                await AppendJournalAsync(
                        state,
                        LiveRenewalJournalCategory.Evidence,
                        LiveRenewalJournalAction.Activation,
                        LiveRenewalJournalOutcome.Applied,
                        "activation.applied",
                        "The remote helper activated the immutable certificate generation.",
                        null,
                        activationPhase.Token)
                    .ConfigureAwait(false);
            }

            using (var remoteVerificationPhase = CreateRecoveryTokenSource())
            {
                state.PendingFailureCode = "remote.verify_failed";
                await InvokeRequiredHelperAsync(
                        remoteSession,
                        RemoteHelperVerbV1.Verify,
                        transactionId,
                        "remote.verify_failed",
                        remoteVerificationPhase.Token)
                    .ConfigureAwait(false);
                await AppendJournalAsync(
                        state,
                        LiveRenewalJournalCategory.Evidence,
                        LiveRenewalJournalAction.RemoteVerification,
                        LiveRenewalJournalOutcome.Succeeded,
                        "remote.verified",
                        "The remote helper verified the active immutable certificate generation.",
                        null,
                        remoteVerificationPhase.Token)
                    .ConfigureAwait(false);
            }

            state.PendingFailureCode = "tls.verification_failed";
            var tlsObservations = await VerifyTlsNamesInParallelAsync(
                    request,
                    state.CertificateLeafSha256)
                .ConfigureAwait(false);
            using (var tlsEvidencePhase = CreateRecoveryTokenSource())
            {
                foreach (var observation in tlsObservations)
                {
                    await AppendJournalAsync(
                            state,
                            LiveRenewalJournalCategory.Evidence,
                            LiveRenewalJournalAction.PublicTlsVerification,
                            LiveRenewalJournalOutcome.Succeeded,
                            request.CertificateTrustMode ==
                            AcmeCertificateTrustMode.UntrustedTest
                                ? "tls.staging_leaf_verified"
                                : "tls.public_chain_verified",
                            request.CertificateTrustMode ==
                            AcmeCertificateTrustMode.UntrustedTest
                                ? "The public endpoint served the expected staging leaf with hostname validation; public chain trust was intentionally not required."
                                : "The public endpoint served the expected leaf with hostname and system-chain validation.",
                            observation.DnsName,
                            tlsEvidencePhase.Token)
                        .ConfigureAwait(false);
                }

                state.PublicTlsVerified = true;
                await AppendJournalAsync(
                        state,
                        LiveRenewalJournalCategory.Evidence,
                        LiveRenewalJournalAction.PublicTlsVerification,
                        LiveRenewalJournalOutcome.Succeeded,
                        "tls.all_names_verified",
                        "Every configured DNS name served the expected certificate under the selected trust policy.",
                        null,
                        tlsEvidencePhase.Token)
                    .ConfigureAwait(false);
            }

            using (var commitPhase = CreateRecoveryTokenSource())
            {
                state.PendingFailureCode = "commit.failed";
                await AppendJournalAsync(
                        state,
                        LiveRenewalJournalCategory.Intent,
                        LiveRenewalJournalAction.Commit,
                        LiveRenewalJournalOutcome.Planned,
                        "commit.planned",
                        "The publicly verified certificate deployment will be committed.",
                        null,
                        commitPhase.Token)
                    .ConfigureAwait(false);
                await InvokeRequiredHelperAsync(
                        remoteSession,
                        RemoteHelperVerbV1.Commit,
                        transactionId,
                        "commit.failed",
                        commitPhase.Token)
                    .ConfigureAwait(false);
                await AppendJournalAsync(
                        state,
                        LiveRenewalJournalCategory.Evidence,
                        LiveRenewalJournalAction.Commit,
                        LiveRenewalJournalOutcome.Applied,
                        "commit.applied",
                        "The publicly verified certificate deployment was committed.",
                        null,
                        commitPhase.Token)
                    .ConfigureAwait(false);
            }

            using (var terminalPhase = CreateRecoveryTokenSource())
            {
                state.PendingFailureCode = "terminal.journal_failed";
                await AppendJournalAsync(
                        state,
                        LiveRenewalJournalCategory.Evidence,
                        LiveRenewalJournalAction.Terminal,
                        LiveRenewalJournalOutcome.Succeeded,
                        "renewal.succeeded",
                        "The live renewal completed with challenge-cleanup and public-TLS evidence.",
                        null,
                        terminalPhase.Token)
                    .ConfigureAwait(false);
            }

            return CreateResult(
                state,
                LiveRenewalStatus.Succeeded,
                failureCode: null);
        }
        catch (WorkflowFailureException exception)
        {
            return await RecoverAndCreateFailureAsync(
                    state,
                    remoteSession,
                    exception.Code,
                    cancelled: false)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            var callerCancellation =
                cancellationToken.IsCancellationRequested &&
                !state.ActivationAttempted;
            return await RecoverAndCreateFailureAsync(
                    state,
                    remoteSession,
                    callerCancellation
                        ? "operation.cancelled"
                        : SafeCode(
                            state.PendingFailureCode,
                            "operation.failed"),
                    callerCancellation)
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            return await RecoverAndCreateFailureAsync(
                    state,
                    remoteSession,
                    SafeCode(
                        state.PendingFailureCode,
                        "operation.failed"),
                    cancelled: false)
                .ConfigureAwait(false);
        }
        finally
        {
            certificateRequest?.Dispose();
            activeAccount?.Dispose();
            if (!ReferenceEquals(storedAccount, activeAccount))
            {
                storedAccount?.Dispose();
            }

            if (remoteSession is not null)
            {
                try
                {
                    await remoteSession.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // Connection disposal cannot reveal secret material or
                    // override an already durable terminal result.
                }
            }
        }
    }

    private async Task<IRemoteSshSession> ConnectAsync(
        LiveHttp01RenewalRequest request,
        CancellationToken cancellationToken)
    {
        byte[]? privateKeyBytes = null;
        try
        {
            privateKeyBytes = secretVault.Read(
                request.SshPrivateKeyReference);
            using var privateKey = new RemotePrivateKeyMaterial(
                privateKeyBytes);
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

    private async Task PublishAndValidateChallengeAsync(
        LiveHttp01RenewalRequest request,
        WorkflowState state,
        AcmeAccount account,
        IRemoteSshSession remoteSession,
        AcmeHttp01Challenge challenge,
        CancellationToken cancellationToken)
    {
        ValidateKeyAuthorization(challenge.KeyAuthorization);
        var token = new RemoteTokenSegment(challenge.Token);
        var identifier = NormalizeChallengeIdentifier(
            challenge.Identifier);
        var challengePath = request.ChallengeWebroot.Combine(token);
        var artifact = new ChallengeArtifact(
            identifier,
            challengePath);

        state.PendingFailureCode = "challenge.upload_failed";
        await AppendJournalAsync(
                state,
                LiveRenewalJournalCategory.Intent,
                LiveRenewalJournalAction.ChallengeWrite,
                LiveRenewalJournalOutcome.Planned,
                "challenge.write_planned",
                "The HTTP-01 challenge response will be published to the configured webroot.",
                challengePath.Value,
                cancellationToken)
            .ConfigureAwait(false);
        state.Challenges.Add(artifact);
        var keyAuthorizationBytes = Encoding.ASCII.GetBytes(
            challenge.KeyAuthorization);
        try
        {
            await using var challengeStream = new MemoryStream(
                keyAuthorizationBytes,
                writable: false);
            await remoteSession.UploadFileAsync(
                    challengePath,
                    challengeStream,
                    RemoteWriteMode.AtomicReplace,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyAuthorizationBytes);
        }

        await AppendJournalAsync(
                state,
                LiveRenewalJournalCategory.Evidence,
                LiveRenewalJournalAction.ChallengeWrite,
                LiveRenewalJournalOutcome.Applied,
                "challenge.published",
                "The HTTP-01 challenge response was published.",
                challengePath.Value,
                cancellationToken)
            .ConfigureAwait(false);

        state.PendingFailureCode = "challenge.verification_failed";
        var verification = await http01Verifier
            .VerifyAsync(
                new Http01VerificationRequest(
                    CreateChallengeUri(
                        identifier,
                        challenge.Token),
                    challenge.KeyAuthorization),
                cancellationToken)
            .ConfigureAwait(false);
        if (!verification.Success)
        {
            throw new WorkflowFailureException(
                SafeCode(
                    verification.Code,
                    "challenge.verification_failed"));
        }

        await AppendJournalAsync(
                state,
                LiveRenewalJournalCategory.Evidence,
                LiveRenewalJournalAction.ChallengeVerification,
                LiveRenewalJournalOutcome.Succeeded,
                "challenge.publicly_verified",
                "The exact HTTP-01 challenge response was independently verified over the public endpoint.",
                identifier,
                cancellationToken)
            .ConfigureAwait(false);

        state.PendingFailureCode = "challenge.acknowledgement_failed";
        var answered = await acmeEngine
            .AnswerHttp01ChallengeAsync(
                account,
                challenge,
                cancellationToken)
            .ConfigureAwait(false);
        if (answered.Status == AcmeResourceStatus.Invalid)
        {
            throw new WorkflowFailureException("challenge.invalid");
        }

        var poll = await acmeEngine
            .PollHttp01ChallengeAsync(
                account,
                challenge,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (poll.TimedOut ||
            poll.Challenge.Status != AcmeResourceStatus.Valid)
        {
            throw new WorkflowFailureException(
                poll.TimedOut
                    ? "challenge.poll_timeout"
                    : "challenge.not_valid");
        }

        await AppendJournalAsync(
                state,
                LiveRenewalJournalCategory.Evidence,
                LiveRenewalJournalAction.ChallengeAcknowledgement,
                LiveRenewalJournalOutcome.Succeeded,
                "challenge.valid",
                "The ACME server reported the independently verified HTTP-01 challenge as valid.",
                identifier,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task CleanupChallengesAsync(
        WorkflowState state,
        IRemoteSshSession remoteSession)
    {
        var outcomes = new bool?[state.Challenges.Count];
        using (var recovery = CreateScaledRecoveryTokenSource(
                   state.Challenges.Count,
                   MaximumParallelCleanupOperations))
        {
            try
            {
                await Parallel.ForEachAsync(
                        Enumerable.Range(0, state.Challenges.Count),
                        new ParallelOptions
                        {
                            MaxDegreeOfParallelism =
                                MaximumParallelCleanupOperations,
                            CancellationToken = recovery.Token,
                        },
                        async (index, phaseCancellationToken) =>
                        {
                            using var filePhase =
                                CancellationTokenSource.CreateLinkedTokenSource(
                                    phaseCancellationToken);
                            filePhase.CancelAfter(recoveryTimeout);
                            try
                            {
                                await remoteSession.RemoveFileAsync(
                                        state.Challenges[index].Path,
                                        MissingFileBehavior.Ignore,
                                        filePhase.Token)
                                    .ConfigureAwait(false);
                                outcomes[index] = true;
                            }
                            catch (Exception)
                            {
                                outcomes[index] = false;
                            }
                        })
                    .ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Each completed worker recorded its result. Any worker that
                // could not start within the scaled overall budget remains
                // conservatively unverified below.
            }
        }

        state.ChallengeCleanupVerified = true;
        for (var index = 0; index < state.Challenges.Count; index++)
        {
            var challenge = state.Challenges[index];
            var removed = outcomes[index] is true;
            var evidenceRecorded = false;
            try
            {
                using var evidenceRecovery = CreateRecoveryTokenSource();
                await AppendJournalAsync(
                        state,
                        LiveRenewalJournalCategory.Evidence,
                        LiveRenewalJournalAction.ChallengeCleanup,
                        removed
                            ? LiveRenewalJournalOutcome.Succeeded
                            : LiveRenewalJournalOutcome.Failed,
                        removed
                            ? "challenge.cleaned"
                            : outcomes[index] is null
                                ? "challenge.cleanup_timeout"
                                : "challenge.cleanup_failed",
                        removed
                            ? "The temporary HTTP-01 challenge response was removed."
                            : "The temporary HTTP-01 challenge response could not be verifiably removed within the bounded cleanup phase.",
                        challenge.Path.Value,
                        evidenceRecovery.Token)
                    .ConfigureAwait(false);
                evidenceRecorded = true;
            }
            catch (Exception)
            {
                // Cleanup remains unverified. Continue recording every other
                // published challenge result.
            }

            state.ChallengeCleanupVerified &=
                removed && evidenceRecorded;
        }
    }

    private async Task<LiveRenewalResult> RecoverAndCreateFailureAsync(
        WorkflowState state,
        IRemoteSshSession? remoteSession,
        string failureCode,
        bool cancelled)
    {
        var safeFailureCode = SafeCode(failureCode, "operation.failed");
        var abortRequired = false;
        var abortVerified = true;
        if (remoteSession is not null && state.ActivationAttempted)
        {
            state.RollbackAttempted = true;
            var journalPlanned = false;
            var helperSucceeded = false;
            var evidenceRecorded = false;
            try
            {
                using var journalRecovery = CreateRecoveryTokenSource();
                await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Intent,
                    LiveRenewalJournalAction.Rollback,
                    LiveRenewalJournalOutcome.Planned,
                    "rollback.planned",
                    "The prior immutable certificate generation will be restored.",
                    null,
                    journalRecovery.Token).ConfigureAwait(false);
                journalPlanned = true;
            }
            catch (Exception)
            {
                // Safety still requires the fixed helper rollback call.
            }

            try
            {
                using var helperRecovery = CreateRecoveryTokenSource();
                var rollback = await remoteSession.InvokeHelperAsync(
                        RemoteHelperVerbV1.Rollback,
                        new RemoteTransactionId(state.Request.OperationId),
                        helperRecovery.Token)
                    .ConfigureAwait(false);
                helperSucceeded = rollback.Succeeded;
            }
            catch (Exception)
            {
                helperSucceeded = false;
            }

            try
            {
                using var evidenceRecovery = CreateRecoveryTokenSource();
                await AppendJournalAsync(
                        state,
                        LiveRenewalJournalCategory.Evidence,
                        LiveRenewalJournalAction.Rollback,
                        helperSucceeded
                            ? LiveRenewalJournalOutcome.Succeeded
                            : LiveRenewalJournalOutcome.Failed,
                        helperSucceeded
                            ? "rollback.succeeded"
                            : "rollback.failed",
                        helperSucceeded
                            ? "The prior immutable certificate generation was restored."
                            : "The prior immutable certificate generation could not be verifiably restored.",
                        null,
                        evidenceRecovery.Token)
                    .ConfigureAwait(false);
                evidenceRecorded = true;
            }
            catch (Exception)
            {
                evidenceRecorded = false;
            }

            state.RollbackSucceeded =
                journalPlanned && helperSucceeded && evidenceRecorded;
            if (helperSucceeded)
            {
                abortRequired = true;
                abortVerified = await AbortBestEffortAsync(
                        state,
                        remoteSession)
                    .ConfigureAwait(false);
            }
        }
        else if (remoteSession is not null && state.RemotePrepareAttempted)
        {
            abortRequired = true;
            abortVerified = await AbortBestEffortAsync(state, remoteSession)
                .ConfigureAwait(false);
        }

        var challengeCleanupRequired =
            state.Challenges.Count > 0 &&
            !state.ChallengeCleanupVerified;
        var status = abortRequired && !abortVerified
            ? LiveRenewalStatus.Blocked
            : state.RollbackAttempted && !state.RollbackSucceeded
                ? LiveRenewalStatus.RollbackRequired
            : challengeCleanupRequired
                ? LiveRenewalStatus.Blocked
            : cancelled
                ? LiveRenewalStatus.Cancelled
                : LiveRenewalStatus.Failed;
        if (status == LiveRenewalStatus.Blocked)
        {
            safeFailureCode = challengeCleanupRequired
                ? "recovery.challenge_cleanup_required"
                : "recovery.abort_required";
            return CreateResult(state, status, safeFailureCode);
        }

        using var terminal = CreateRecoveryTokenSource();
        try
        {
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.Terminal,
                    status == LiveRenewalStatus.Cancelled
                        ? LiveRenewalJournalOutcome.Cancelled
                        : LiveRenewalJournalOutcome.Failed,
                    status == LiveRenewalStatus.RollbackRequired
                        ? "renewal.rollback_required"
                        : status == LiveRenewalStatus.Cancelled
                            ? "renewal.cancelled"
                            : "renewal.failed",
                    status == LiveRenewalStatus.RollbackRequired
                        ? "The live renewal failed and automatic rollback could not be durably verified."
                        : status == LiveRenewalStatus.Cancelled
                            ? "The live renewal was cancelled before the activation boundary."
                            : "The live renewal failed without exposing dependency exception details.",
                    null,
                    terminal.Token)
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The result remains conservative even when terminal persistence
            // is unavailable; the caller can retry/reconcile by operation ID.
        }

        return CreateResult(state, status, safeFailureCode);
    }

    private async Task<bool> AbortBestEffortAsync(
        WorkflowState state,
        IRemoteSshSession remoteSession)
    {
        var journalPlanned = false;
        try
        {
            using var journalRecovery = CreateRecoveryTokenSource();
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Intent,
                    LiveRenewalJournalAction.Abort,
                    LiveRenewalJournalOutcome.Planned,
                    "abort.planned",
                    "The inactive remote transaction will be discarded, its incoming private-key material destroyed, and its generation released.",
                    null,
                    journalRecovery.Token)
                .ConfigureAwait(false);
            journalPlanned = true;
        }
        catch (Exception)
        {
            // Still invoke the fixed abort command as a best-effort cleanup.
        }

        var succeeded = false;
        var evidenceRecorded = false;
        try
        {
            using var helperRecovery = CreateRecoveryTokenSource();
            var result = await remoteSession.InvokeHelperAsync(
                    RemoteHelperVerbV1.Abort,
                    new RemoteTransactionId(state.Request.OperationId),
                    helperRecovery.Token)
                .ConfigureAwait(false);
            succeeded = result.Succeeded;
        }
        catch (Exception)
        {
            succeeded = false;
        }

        try
        {
            using var evidenceRecovery = CreateRecoveryTokenSource();
            await AppendJournalAsync(
                    state,
                    LiveRenewalJournalCategory.Evidence,
                    LiveRenewalJournalAction.Abort,
                    succeeded
                        ? LiveRenewalJournalOutcome.Succeeded
                        : LiveRenewalJournalOutcome.Failed,
                    succeeded ? "abort.succeeded" : "abort.failed",
                    succeeded
                        ? "The inactive remote transaction was discarded, its incoming private-key material destroyed, and its generation released."
                        : "The inactive remote transaction and its incoming private-key material could not be verifiably discarded.",
                    null,
                    evidenceRecovery.Token)
                .ConfigureAwait(false);
            evidenceRecorded = true;
        }
        catch (Exception)
        {
            // Best-effort recovery evidence cannot replace the primary result.
        }

        return journalPlanned && succeeded && evidenceRecorded;
    }

    private async Task AppendJournalAsync(
        WorkflowState state,
        LiveRenewalJournalCategory category,
        LiveRenewalJournalAction action,
        LiveRenewalJournalOutcome outcome,
        string code,
        string description,
        string? subject,
        CancellationToken cancellationToken)
    {
        var entry = new LiveRenewalJournalEntry(
            state.Request.OperationId,
            state.NextSequence(),
            category,
            action,
            outcome,
            timeProvider.GetUtcNow(),
            code,
            description,
            subject);
        await journal.AppendAsync(entry, cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task InvokeRequiredHelperAsync(
        IRemoteSshSession remoteSession,
        RemoteHelperVerbV1 verb,
        RemoteTransactionId transactionId,
        string failureCode,
        CancellationToken cancellationToken)
    {
        var result = await remoteSession
            .InvokeHelperAsync(verb, transactionId, cancellationToken)
            .ConfigureAwait(false);
        if (!result.Succeeded)
        {
            throw new WorkflowFailureException(failureCode);
        }
    }

    private static async Task InvokePrepareAsync(
        IRemoteSshSession remoteSession,
        RemoteTransactionId transactionId,
        RemotePosixPath incomingRoot,
        CancellationToken cancellationToken)
    {
        var result = await remoteSession
            .InvokeHelperAsync(
                RemoteHelperVerbV1.Prepare,
                transactionId,
                cancellationToken)
            .ConfigureAwait(false);
        if (!result.Succeeded)
        {
            throw new WorkflowFailureException("remote.prepare_failed");
        }

        HelperPrepareResponse? response;
        try
        {
            response = JsonSerializer.Deserialize<HelperPrepareResponse>(
                result.StandardOutput,
                helperJsonOptions);
        }
        catch (JsonException)
        {
            throw new WorkflowFailureException(
                "remote.prepare_response_invalid");
        }

        if (response is null ||
            response.Version != 1 ||
            !response.Success ||
            !string.Equals(
                response.Code,
                "helper.prepared",
                StringComparison.Ordinal) ||
            !string.Equals(
                response.TransactionId,
                transactionId.ToString(),
                StringComparison.Ordinal))
        {
            throw new WorkflowFailureException(
                "remote.prepare_response_invalid");
        }

        RemotePosixPath uploadPath;
        try
        {
            uploadPath = RemotePosixPath.Parse(response.UploadPath ?? string.Empty);
        }
        catch (ArgumentException)
        {
            throw new WorkflowFailureException(
                "remote.prepare_response_invalid");
        }

        var expectedPath = incomingRoot.Combine(
            new RemotePathSegment(transactionId.ToString()));
        if (uploadPath != expectedPath)
        {
            throw new WorkflowFailureException(
                "remote.prepare_path_mismatch");
        }
    }

    private async Task<IReadOnlyList<TlsVerificationObservation>>
        VerifyTlsNamesInParallelAsync(
            LiveHttp01RenewalRequest request,
            string? expectedLeafSha256)
    {
        if (string.IsNullOrWhiteSpace(expectedLeafSha256))
        {
            throw new WorkflowFailureException(
                "tls.expected_leaf_missing");
        }

        var observations = new TlsVerificationObservation[request.DnsNames.Count];
        var waveCount = checked(
            (request.DnsNames.Count + MaximumParallelTlsVerifications - 1) /
            MaximumParallelTlsVerifications);
        var scaledTicks = checked(recoveryTimeout.Ticks * waveCount);
        var overallTimeout = TimeSpan.FromTicks(
            Math.Min(scaledTicks, TimeSpan.FromMinutes(5).Ticks));
        using var overallPhase = new CancellationTokenSource(overallTimeout);
        await Parallel.ForEachAsync(
                Enumerable.Range(0, request.DnsNames.Count),
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = MaximumParallelTlsVerifications,
                    CancellationToken = overallPhase.Token,
                },
                async (index, phaseCancellationToken) =>
                {
                    var dnsName = request.DnsNames[index];
                    using var probePhase =
                        CancellationTokenSource.CreateLinkedTokenSource(
                            phaseCancellationToken);
                    probePhase.CancelAfter(recoveryTimeout);
                    var result = await tlsVerifier
                        .VerifyAsync(
                            new PublicTlsVerificationRequest(
                                dnsName,
                                request.TlsPort,
                                expectedLeafSha256,
                                request.TlsTrustPolicy),
                            probePhase.Token)
                        .ConfigureAwait(false);
                    if (!result.Success ||
                        !string.Equals(
                            NormalizeOptionalSha256(
                                result.ObservedLeafSha256),
                            expectedLeafSha256,
                            StringComparison.Ordinal))
                    {
                        throw new WorkflowFailureException(
                            SafeCode(
                                result.Code,
                                "tls.verification_failed"));
                    }

                    observations[index] = new TlsVerificationObservation(
                        dnsName);
                })
            .ConfigureAwait(false);
        return Array.AsReadOnly(observations);
    }

    private static IReadOnlyList<AcmeHttp01Challenge> ValidateChallenges(
        IReadOnlyList<AcmeHttp01Challenge> challenges,
        IReadOnlyList<string> requestedDnsNames)
    {
        ArgumentNullException.ThrowIfNull(challenges);
        if (challenges.Count != requestedDnsNames.Count)
        {
            throw new WorkflowFailureException(
                "challenge.identifiers_mismatch");
        }

        var requested = new HashSet<string>(
            requestedDnsNames,
            StringComparer.OrdinalIgnoreCase);
        var observed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var challenge in challenges)
        {
            var identifier = NormalizeChallengeIdentifier(
                challenge.Identifier);
            if (challenge.IsWildcard ||
                !requested.Contains(identifier) ||
                !observed.Add(identifier))
            {
                throw new WorkflowFailureException(
                    "challenge.identifiers_mismatch");
            }

            _ = new RemoteTokenSegment(challenge.Token);
            ValidateKeyAuthorization(challenge.KeyAuthorization);
        }

        return challenges;
    }

    private static void ValidateOrder(
        AcmeOrder order,
        IReadOnlyList<string> requestedDnsNames,
        string failureCode)
    {
        ArgumentNullException.ThrowIfNull(order);
        var requested = new HashSet<string>(
            requestedDnsNames,
            StringComparer.OrdinalIgnoreCase);
        var observed = new HashSet<string>(
            order.DnsIdentifiers.Select(
                static identifier => identifier.TrimEnd('.')),
            StringComparer.OrdinalIgnoreCase);
        if (!requested.SetEquals(observed))
        {
            throw new WorkflowFailureException(failureCode);
        }
    }

    private static void ValidateCertificateChain(
        AcmeCertificateChain certificateChain,
        long maximumTransferBytes)
    {
        ArgumentNullException.ThrowIfNull(certificateChain);
        if (string.IsNullOrWhiteSpace(certificateChain.LeafCertificatePem) ||
            string.IsNullOrWhiteSpace(certificateChain.FullChainPem) ||
            Encoding.UTF8.GetByteCount(certificateChain.FullChainPem) >
            maximumTransferBytes)
        {
            throw new WorkflowFailureException(
                "certificate.chain_invalid");
        }
    }

    private static CertificateIdentity InspectCertificateIdentity(
        string certificateChainPem,
        IReadOnlyList<string> requestedDnsNames)
    {
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(
                certificateChainPem);
            var subjectAlternativeNames = certificate.Extensions
                .OfType<X509SubjectAlternativeNameExtension>()
                .SingleOrDefault();
            if (subjectAlternativeNames is null)
            {
                throw new WorkflowFailureException(
                    "certificate.names_mismatch");
            }

            var observed = new HashSet<string>(
                subjectAlternativeNames.EnumerateDnsNames(),
                StringComparer.OrdinalIgnoreCase);
            var requested = new HashSet<string>(
                requestedDnsNames,
                StringComparer.OrdinalIgnoreCase);
            if (!requested.SetEquals(observed))
            {
                throw new WorkflowFailureException(
                    "certificate.names_mismatch");
            }

            using var publicKey = certificate.GetECDsaPublicKey();
            if (publicKey is null || publicKey.KeySize != 256)
            {
                throw new WorkflowFailureException(
                    "certificate.public_key_invalid");
            }

            var subjectPublicKeyInfo = publicKey.ExportSubjectPublicKeyInfo();
            try
            {
                return new CertificateIdentity(
                    certificate.GetCertHashString(
                        HashAlgorithmName.SHA256),
                    Convert.ToHexString(
                        SHA256.HashData(subjectPublicKeyInfo)),
                    new DateTimeOffset(
                        certificate.NotBefore.ToUniversalTime()),
                    new DateTimeOffset(
                        certificate.NotAfter.ToUniversalTime()));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            }
        }
        catch (CryptographicException)
        {
            throw new WorkflowFailureException(
                "certificate.material_invalid");
        }
    }

    private static void ValidateKeyAuthorization(string keyAuthorization)
    {
        if (string.IsNullOrWhiteSpace(keyAuthorization) ||
            keyAuthorization.Length > 2_048 ||
            keyAuthorization.Any(
                static character =>
                    character > 127 || char.IsControl(character)))
        {
            throw new WorkflowFailureException(
                "challenge.key_authorization_invalid");
        }
    }

    private static Uri CreateChallengeUri(
        string identifier,
        string token)
    {
        var builder = new UriBuilder(
            Uri.UriSchemeHttp,
            identifier.TrimEnd('.'),
            80,
            $"/.well-known/acme-challenge/{token}");
        return builder.Uri;
    }

    private static string NormalizeChallengeIdentifier(
        string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier) ||
            identifier.Length > 254 ||
            !string.Equals(identifier, identifier.Trim(), StringComparison.Ordinal) ||
            identifier.Any(char.IsControl))
        {
            throw new WorkflowFailureException(
                "challenge.identifier_invalid");
        }

        return identifier.TrimEnd('.').ToLowerInvariant();
    }

    private static string NormalizeSha256(
        string fingerprint,
        string failureCode)
    {
        var normalized = NormalizeOptionalSha256(fingerprint);
        if (normalized is null)
        {
            throw new WorkflowFailureException(failureCode);
        }

        return normalized;
    }

    private static string? NormalizeOptionalSha256(string? fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            return null;
        }

        var normalized = fingerprint
            .Replace(":", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();
        return normalized.Length == 64 &&
            normalized.All(static character => Uri.IsHexDigit(character))
                ? normalized
                : null;
    }

    private static string SafeCode(
        string? candidate,
        string fallback)
    {
        if (!string.IsNullOrWhiteSpace(candidate) &&
            candidate.Length <= 128 &&
            candidate.All(
                static character =>
                    character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-'))
        {
            return candidate;
        }

        return fallback;
    }

    private CancellationTokenSource CreateRecoveryTokenSource() =>
        new(recoveryTimeout);

    private CancellationTokenSource CreateScaledRecoveryTokenSource(
        int itemCount,
        int maximumDegreeOfParallelism)
    {
        var waveCount = Math.Max(
            1,
            (itemCount + maximumDegreeOfParallelism - 1) /
            maximumDegreeOfParallelism);
        var maximumTicks = TimeSpan.FromMinutes(5).Ticks;
        var scaledTicks = recoveryTimeout.Ticks > maximumTicks / waveCount
            ? maximumTicks
            : recoveryTimeout.Ticks * waveCount;
        return new CancellationTokenSource(TimeSpan.FromTicks(scaledTicks));
    }

    private static LiveRenewalResult CreateResult(
        WorkflowState state,
        LiveRenewalStatus status,
        string? failureCode) =>
        new(
            state.Request.OperationId,
            status,
            failureCode,
            state.ChallengeCleanupVerified,
            state.PublicTlsVerified,
            state.ActivationAttempted,
            state.RollbackAttempted,
            state.RollbackSucceeded,
            state.CertificateLeafSha256,
            state.PublicKeySha256,
            state.NotBeforeUtc,
            state.NotAfterUtc,
            state.CertificatePrivateKeyReference,
            state.Request.TlsTrustPolicy);

    private sealed class WorkflowState
    {
        private long sequence;

        public WorkflowState(LiveHttp01RenewalRequest request)
        {
            Request = request;
        }

        public LiveHttp01RenewalRequest Request { get; }

        public List<ChallengeArtifact> Challenges { get; } = [];

        public bool ChallengeCleanupVerified { get; set; }

        public bool RemotePrepareAttempted { get; set; }

        public bool ActivationAttempted { get; set; }

        public bool PublicTlsVerified { get; set; }

        public bool RollbackAttempted { get; set; }

        public bool RollbackSucceeded { get; set; }

        public string? CertificateLeafSha256 { get; set; }

        public string? PublicKeySha256 { get; set; }

        public DateTimeOffset? NotBeforeUtc { get; set; }

        public DateTimeOffset? NotAfterUtc { get; set; }

        public SecretReference? CertificatePrivateKeyReference { get; set; }

        public string PendingFailureCode { get; set; } = "operation.failed";

        public long NextSequence() => Interlocked.Increment(ref sequence);
    }

    private sealed record ChallengeArtifact(
        string Identifier,
        RemotePosixPath Path);

    private sealed record TlsVerificationObservation(string DnsName);

    private sealed record HelperPrepareResponse(
        int Version,
        bool Success,
        string? Code,
        string? TransactionId,
        string? UploadPath);

    private sealed record CertificateIdentity(
        string CertificateLeafSha256,
        string PublicKeySha256,
        DateTimeOffset NotBeforeUtc,
        DateTimeOffset NotAfterUtc);

    private sealed class WorkflowFailureException : Exception
    {
        public WorkflowFailureException(string code)
            : base("The live renewal workflow failed.")
        {
            Code = SafeCode(code, "operation.failed");
        }

        public string Code { get; }
    }
}
