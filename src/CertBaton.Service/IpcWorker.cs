using System.Reflection;
using System.Security.Cryptography;
using CertBaton.Application.Remote;
using CertBaton.Application.Simulation.Persistence;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;

namespace CertBaton.Service;

public sealed partial class IpcWorker : BackgroundService
{
    private readonly CertBatonPipeServer pipeServer;
    private readonly ISimulationCoordinator simulationCoordinator;
    private readonly SimulationAccessPolicy simulationAccessPolicy;
    private readonly ILogger<IpcWorker> logger;
    private readonly TimeProvider timeProvider;
    private readonly LiveMaintenanceGate maintenanceGate;
    private readonly IVaultProbe? vaultProbe;
    private readonly ICredentialImporter? credentialImporter;
    private readonly ISshConnectionProbe? sshConnectionProbe;
    private readonly ILiveTargetCoordinator? liveTargetCoordinator;
    private readonly ILiveRenewalCoordinator? liveRenewalCoordinator;
    private readonly DateTimeOffset startedAtUtc;
    private readonly string serviceVersion;

    public IpcWorker(
        CertBatonPipeServer pipeServer,
        ISimulationCoordinator simulationCoordinator,
        SimulationAccessPolicy simulationAccessPolicy,
        ILogger<IpcWorker> logger,
        TimeProvider timeProvider,
        IVaultProbe? vaultProbe = null,
        ICredentialImporter? credentialImporter = null,
        ISshConnectionProbe? sshConnectionProbe = null,
        ILiveTargetCoordinator? liveTargetCoordinator = null,
        ILiveRenewalCoordinator? liveRenewalCoordinator = null,
        LiveMaintenanceGate? maintenanceGate = null)
    {
        this.pipeServer = pipeServer;
        this.simulationCoordinator = simulationCoordinator;
        this.simulationAccessPolicy = simulationAccessPolicy;
        this.logger = logger;
        this.timeProvider = timeProvider;
        this.maintenanceGate = maintenanceGate ?? new LiveMaintenanceGate();
        this.vaultProbe = vaultProbe;
        this.credentialImporter = credentialImporter;
        this.sshConnectionProbe = sshConnectionProbe;
        this.liveTargetCoordinator = liveTargetCoordinator;
        this.liveRenewalCoordinator = liveRenewalCoordinator;
        startedAtUtc = timeProvider.GetUtcNow();
        serviceVersion = typeof(IpcWorker).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "unknown";
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LogIpcStarting(logger, IpcProtocol.CurrentVersion);

        await pipeServer.RunAsync(HandleRequestAsync, stoppingToken).ConfigureAwait(false);

        LogIpcStopped(logger);
    }

    internal async ValueTask<IpcResponse> HandleRequestAsync(
        IpcRequest request,
        PipeClientIdentity identity,
        CancellationToken cancellationToken)
    {
        if (!request.TryValidateMethodPayload(out var requestError))
        {
            if (request.CredentialPayload?.Secret is { } invalidSecret)
            {
                CryptographicOperations.ZeroMemory(invalidSecret);
            }

            if (request.SshConnectionProbePayload?.PrivateKey is { } invalidProbeKey)
            {
                CryptographicOperations.ZeroMemory(invalidProbeKey);
            }

            return IpcResponse.Failed(
                request.RequestId,
                "invalid_request",
                requestError ?? "The request payload is invalid.");
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.HealthMethod,
                StringComparison.Ordinal))
        {
            return IpcResponse.Succeeded(
                request.RequestId,
                new HealthSnapshot(
                    "healthy",
                    serviceVersion,
                    startedAtUtc,
                    timeProvider.GetUtcNow()));
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.SimulationLatestMethod,
                StringComparison.Ordinal))
        {
            var latest = simulationCoordinator.Latest;
            return latest is null
                ? IpcResponse.Failed(
                    request.RequestId,
                    "simulation_not_found",
                    "No simulated renewal has been recorded yet.")
                : IpcResponse.Succeeded(
                    request.RequestId,
                    SimulationContractMapper.ToContract(latest));
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.VaultProbeMethod,
                StringComparison.Ordinal))
        {
            if (!simulationAccessPolicy.CanStart(identity))
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "vault_probe_forbidden",
                    "This Windows identity is not authorized to probe the service vault.");
            }

            if (vaultProbe is null)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "vault_probe_unavailable",
                    "The service vault probe is not configured.");
            }

            try
            {
                return IpcResponse.Succeeded(
                    request.RequestId,
                    vaultProbe.Run());
            }
            catch (Exception exception) when (
                exception is CryptographicException or
                IOException or
                UnauthorizedAccessException)
            {
                LogVaultProbeFailed(logger, exception);
                return IpcResponse.Failed(
                    request.RequestId,
                    "vault_probe_failed",
                    "The service could not complete its protected-storage probe.");
            }
        }

        if (IsStateMutation(request.Method) && maintenanceGate.IsPaused)
        {
            if (request.CredentialPayload?.Secret is { } pausedSecret)
            {
                CryptographicOperations.ZeroMemory(pausedSecret);
            }

            return IpcResponse.Failed(
                request.RequestId,
                "service_maintenance",
                "State-changing work is paused while installation maintenance is in progress.");
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.SshConnectionProbeMethod,
                StringComparison.Ordinal))
        {
            var payload = request.SshConnectionProbePayload ??
                throw new InvalidOperationException(
                    "A validated SSH/SFTP connection test did not contain its payload.");
            try
            {
                if (!simulationAccessPolicy.CanStart(identity))
                {
                    return IpcResponse.Failed(
                        request.RequestId,
                        "connection_probe_forbidden",
                        "Administrator approval is required to test a hosting connection.");
                }

                if (sshConnectionProbe is null)
                {
                    return IpcResponse.Failed(
                        request.RequestId,
                        "connection_probe_unavailable",
                        "SSH/SFTP connection testing is not configured.");
                }

                var endpoint = RemoteSshEndpoint.Create(
                    payload.Host,
                    payload.Port,
                    payload.Username);
                using var privateKey = new RemotePrivateKeyMaterial(
                    payload.PrivateKey);
                var result = await sshConnectionProbe.ProbeAsync(
                        endpoint,
                        privateKey,
                        cancellationToken)
                    .ConfigureAwait(false);
                return IpcResponse.Succeeded(
                    request.RequestId,
                    new SshConnectionProbeSnapshot(
                        LiveContractValues.SshSftpConnector,
                        result.Endpoint.Host,
                        result.Endpoint.Port,
                        result.Endpoint.Username,
                        result.HostKeyAlgorithm,
                        result.HostKeyFingerprintSha256,
                        result.HostKeyBase64,
                        result.AuthenticationSucceeded,
                        result.SftpAvailable,
                        timeProvider.GetUtcNow()));
            }
            catch (Exception exception) when (
                exception is ArgumentException or
                SshConnectionProbeException or
                IOException or
                UnauthorizedAccessException)
            {
                LogLiveRequestFailed(
                    logger,
                    IpcProtocol.SshConnectionProbeMethod,
                    exception);
                return IpcResponse.Failed(
                    request.RequestId,
                    "connection_probe_failed",
                    "CertBaton could not sign in to this SSH/SFTP server with the selected key.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload.PrivateKey);
            }
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.CredentialImportSshPrivateKeyMethod,
                StringComparison.Ordinal))
        {
            var secret = request.CredentialPayload?.Secret ??
                throw new InvalidOperationException(
                    "A validated credential import did not contain secret bytes.");
            try
            {
                if (!simulationAccessPolicy.CanStart(identity))
                {
                    return IpcResponse.Failed(
                        request.RequestId,
                        "credential_import_forbidden",
                        "This Windows identity is not authorized to import credentials.");
                }

                if (credentialImporter is null)
                {
                    return IpcResponse.Failed(
                        request.RequestId,
                        "credential_import_unavailable",
                        "Credential import is not configured.");
                }

                return IpcResponse.Succeeded(
                    request.RequestId,
                    credentialImporter.ImportSshPrivateKey(secret));
            }
            catch (Exception exception) when (
                exception is CryptographicException or
                InvalidDataException or
                IOException or
                UnauthorizedAccessException)
            {
                LogCredentialImportFailed(logger, exception);
                return IpcResponse.Failed(
                    request.RequestId,
                    "credential_import_failed",
                    "The service could not validate and protect the SSH private key.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.TargetEnrollMethod,
                StringComparison.Ordinal))
        {
            if (!simulationAccessPolicy.CanStart(identity))
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "target_enroll_forbidden",
                    "This Windows identity is not authorized to enroll a live target.");
            }

            if (liveTargetCoordinator is null)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "target_enroll_unavailable",
                    "Live target enrollment is not configured.");
            }

            try
            {
                return IpcResponse.Succeeded(
                    request.RequestId,
                    liveTargetCoordinator.Enroll(
                        request.TargetEnrollmentPayload ??
                            throw new InvalidOperationException(
                                "A validated target enrollment did not contain its payload."),
                        identity.UserSid));
            }
            catch (Exception exception) when (
                exception is ArgumentException or
                InvalidOperationException or
                IOException or
                UnauthorizedAccessException)
            {
                LogLiveRequestFailed(logger, IpcProtocol.TargetEnrollMethod, exception);
                return IpcResponse.Failed(
                    request.RequestId,
                    "target_enroll_failed",
                    "The service could not persist the live target configuration.");
            }
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.TargetListMethod,
                StringComparison.Ordinal))
        {
            if (!simulationAccessPolicy.CanStart(identity))
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "target_list_forbidden",
                    "This Windows identity is not authorized to read live target metadata.");
            }

            if (liveTargetCoordinator is null)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "target_list_unavailable",
                    "Live target storage is not configured.");
            }

            try
            {
                return IpcResponse.Succeeded(
                    request.RequestId,
                    liveTargetCoordinator.List());
            }
            catch (Exception exception) when (
                exception is InvalidOperationException or
                IOException or
                UnauthorizedAccessException)
            {
                LogLiveRequestFailed(logger, IpcProtocol.TargetListMethod, exception);
                return IpcResponse.Failed(
                    request.RequestId,
                    "target_list_failed",
                    "The service could not read live target metadata.");
            }
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.RenewalStartMethod,
                StringComparison.Ordinal))
        {
            if (!simulationAccessPolicy.CanStart(identity))
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "renewal_start_forbidden",
                    "This Windows identity is not authorized to start a live renewal.");
            }

            if (liveRenewalCoordinator is null)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "renewal_start_unavailable",
                    "Live renewal is not configured.");
            }

            try
            {
                return IpcResponse.Succeeded(
                    request.RequestId,
                    await liveRenewalCoordinator.StartAsync(
                            request.RenewalStartPayload ??
                                throw new InvalidOperationException(
                                    "A validated renewal start did not contain its payload."),
                            identity.UserSid,
                            cancellationToken)
                        .ConfigureAwait(false));
            }
            catch (Exception exception) when (
                exception is ArgumentException or
                InvalidOperationException or
                IOException or
                UnauthorizedAccessException)
            {
                LogLiveRequestFailed(logger, IpcProtocol.RenewalStartMethod, exception);
                return IpcResponse.Failed(
                    request.RequestId,
                    "renewal_start_failed",
                    "The service could not accept the live renewal request.");
            }
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.RenewalGetMethod,
                StringComparison.Ordinal))
        {
            if (!simulationAccessPolicy.CanStart(identity))
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "renewal_get_forbidden",
                    "This Windows identity is not authorized to read live renewal evidence.");
            }

            if (liveRenewalCoordinator is null)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "renewal_get_unavailable",
                    "Live renewal is not configured.");
            }

            try
            {
                var operationId = request.RenewalQueryPayload?.OperationId ??
                    throw new InvalidOperationException(
                        "A validated renewal query did not contain its payload.");
                var operation = liveRenewalCoordinator.Find(operationId);
                return operation is null
                    ? IpcResponse.Failed(
                        request.RequestId,
                        "renewal_not_found",
                        "The requested live renewal operation was not found.")
                    : IpcResponse.Succeeded(request.RequestId, operation);
            }
            catch (Exception exception) when (
                exception is ArgumentException or
                InvalidOperationException or
                IOException or
                UnauthorizedAccessException)
            {
                LogLiveRequestFailed(logger, IpcProtocol.RenewalGetMethod, exception);
                return IpcResponse.Failed(
                    request.RequestId,
                    "renewal_get_failed",
                    "The service could not read the live renewal operation.");
            }
        }

        if (string.Equals(
                request.Method,
                IpcProtocol.SimulationStartMethod,
                StringComparison.Ordinal))
        {
            if (!simulationAccessPolicy.CanStart(identity))
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "simulation_start_forbidden",
                    "This Windows identity is not authorized to start the development simulator.");
            }

            var payload = request.Payload
                ?? throw new InvalidOperationException(
                    "A validated simulation start request did not contain its payload.");
            var failureStage = payload.FailureStage is null
                ? (CertBaton.Domain.Renewals.RenewalStage?)null
                : SimulationContractMapper.ParseStage(payload.FailureStage);

            try
            {
                var details = await simulationCoordinator
                    .StartAsync(
                        payload.IdempotencyKey,
                        failureStage,
                        cancellationToken)
                    .ConfigureAwait(false);
                return IpcResponse.Succeeded(
                    request.RequestId,
                    SimulationContractMapper.ToContract(details));
            }
            catch (SimulationAlreadyActiveException exception)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "simulation_already_active",
                    exception.Message);
            }
            catch (SimulationIdempotencyConflictException exception)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "simulation_idempotency_conflict",
                    exception.Message);
            }
        }

        return IpcResponse.Failed(
            request.RequestId,
            "method_not_found",
            "The requested method is not available.");
    }

    private static bool IsStateMutation(string method) =>
        string.Equals(
            method,
            IpcProtocol.CredentialImportSshPrivateKeyMethod,
            StringComparison.Ordinal) ||
        string.Equals(
            method,
            IpcProtocol.TargetEnrollMethod,
            StringComparison.Ordinal) ||
        string.Equals(
            method,
            IpcProtocol.RenewalStartMethod,
            StringComparison.Ordinal) ||
        string.Equals(
            method,
            IpcProtocol.SimulationStartMethod,
            StringComparison.Ordinal);

    [LoggerMessage(
        EventId = 1000,
        Level = LogLevel.Information,
        Message = "CertBaton service IPC version {ProtocolVersion} is starting.")]
    private static partial void LogIpcStarting(ILogger logger, int protocolVersion);

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Information,
        Message = "CertBaton service IPC has stopped.")]
    private static partial void LogIpcStopped(ILogger logger);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Error,
        Message = "The CertBaton service vault probe failed.")]
    private static partial void LogVaultProbeFailed(
        ILogger logger,
        Exception exception);

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Error,
        Message = "The CertBaton SSH credential import failed.")]
    private static partial void LogCredentialImportFailed(
        ILogger logger,
        Exception exception);

    [LoggerMessage(
        EventId = 1004,
        Level = LogLevel.Error,
        Message = "The CertBaton live request '{Method}' failed.")]
    private static partial void LogLiveRequestFailed(
        ILogger logger,
        string method,
        Exception exception);
}
