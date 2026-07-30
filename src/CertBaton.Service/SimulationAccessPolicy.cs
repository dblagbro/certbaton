using CertBaton.Ipc.NamedPipes;

namespace CertBaton.Service;

public sealed class SimulationAccessPolicy
{
    private readonly PipeServerSecurityProfile securityProfile;

    public SimulationAccessPolicy(IpcServerOptions serverOptions)
    {
        ArgumentNullException.ThrowIfNull(serverOptions);
        securityProfile = serverOptions.SecurityProfile;
    }

    public bool CanStart(PipeClientIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        return securityProfile == PipeServerSecurityProfile.CurrentUserDevelopment ||
            identity.IsAdministrator;
    }
}
