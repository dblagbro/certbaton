using System.Reflection;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;

namespace CertBaton.Service;

public sealed partial class IpcWorker : BackgroundService
{
    private readonly CertBatonPipeServer pipeServer;
    private readonly ILogger<IpcWorker> logger;
    private readonly TimeProvider timeProvider;
    private readonly DateTimeOffset startedAtUtc;
    private readonly string serviceVersion;

    public IpcWorker(
        CertBatonPipeServer pipeServer,
        ILogger<IpcWorker> logger,
        TimeProvider timeProvider)
    {
        this.pipeServer = pipeServer;
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

    private ValueTask<IpcResponse> HandleRequestAsync(
        IpcRequest request,
        PipeClientIdentity identity,
        CancellationToken cancellationToken)
    {
        _ = cancellationToken;

        if (!string.Equals(request.Method, IpcProtocol.HealthMethod, StringComparison.Ordinal))
        {
            return ValueTask.FromResult(
                IpcResponse.Failed(
                    request.RequestId,
                    "method_not_found",
                    "The requested method is not available."));
        }

        _ = identity;

        return ValueTask.FromResult(
            IpcResponse.Succeeded(
                request.RequestId,
                new HealthSnapshot(
                    "healthy",
                    serviceVersion,
                    startedAtUtc,
                    timeProvider.GetUtcNow())));
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
