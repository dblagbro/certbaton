using CertBaton.Contracts;

namespace CertBaton.Ipc.NamedPipes;

public sealed record IpcClientOptions
{
    public string PipeName { get; init; } = IpcProtocol.DefaultPipeName;

    public TimeSpan ConnectTimeout { get; init; } = IpcProtocol.DefaultRequestTimeout;

    internal int? DevelopmentServerProcessId { get; init; }
}
