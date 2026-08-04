using CertBaton.Application.Remote;

namespace CertBaton.Remote.Ssh;

public sealed class SshHostKeyPinMismatchException : Exception
{
    public SshHostKeyPinMismatchException(RemoteSshEndpoint endpoint, Exception innerException)
        : base($"The SSH host key for {endpoint.Host}:{endpoint.Port} did not match the enrolled pin.", innerException)
    {
        Endpoint = endpoint;
    }

    public RemoteSshEndpoint Endpoint { get; }
}
