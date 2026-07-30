using CertBaton.Contracts;

namespace CertBaton.Ipc.NamedPipes;

public enum PipeServerSecurityProfile
{
    InstalledService,
    CurrentUserDevelopment,
}

public sealed record IpcServerOptions
{
    public string PipeName { get; init; } = IpcProtocol.DefaultPipeName;

    public int MaximumConcurrentClients { get; init; } = 8;

    public TimeSpan ClientRequestTimeout { get; init; } = TimeSpan.FromSeconds(5);

    public PipeServerSecurityProfile SecurityProfile { get; init; } =
        PipeServerSecurityProfile.InstalledService;
}
