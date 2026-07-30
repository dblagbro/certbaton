using System.Reflection;
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
    private readonly DateTimeOffset startedAtUtc;
    private readonly string serviceVersion;

    public IpcWorker(
        CertBatonPipeServer pipeServer,
        ISimulationCoordinator simulationCoordinator,
        SimulationAccessPolicy simulationAccessPolicy,
        ILogger<IpcWorker> logger,
        TimeProvider timeProvider)
    {
        this.pipeServer = pipeServer;
        this.simulationCoordinator = simulationCoordinator;
        this.simulationAccessPolicy = simulationAccessPolicy;
        this.logger = logger;
        this.timeProvider = timeProvider;
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
}
