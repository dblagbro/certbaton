namespace CertBaton.Application.Remote;

public sealed record SshConnectionProbeResult(
    RemoteSshEndpoint Endpoint,
    string HostKeyAlgorithm,
    string HostKeyFingerprintSha256,
    string HostKeyBase64,
    bool AuthenticationSucceeded,
    bool SftpAvailable);

public interface ISshConnectionProbe
{
    Task<SshConnectionProbeResult> ProbeAsync(
        RemoteSshEndpoint endpoint,
        RemotePrivateKeyMaterial privateKey,
        CancellationToken cancellationToken);
}

public sealed class SshConnectionProbeException : IOException
{
    public SshConnectionProbeException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
