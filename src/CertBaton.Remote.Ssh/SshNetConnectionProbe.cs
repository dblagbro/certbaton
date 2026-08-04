using System.Security.Cryptography;
using CertBaton.Application.Remote;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace CertBaton.Remote.Ssh;

public sealed class SshNetConnectionProbe : ISshConnectionProbe
{
    public async Task<SshConnectionProbeResult> ProbeAsync(
        RemoteSshEndpoint endpoint,
        RemotePrivateKeyMaterial privateKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(privateKey);

        try
        {
            return await ProbeCoreAsync(
                    endpoint,
                    privateKey,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SshException or
            IOException or
            CryptographicException or
            InvalidOperationException or
            NotSupportedException)
        {
            throw new SshConnectionProbeException(
                "CertBaton could not authenticate to the SSH/SFTP server.",
                exception);
        }
    }

    private static async Task<SshConnectionProbeResult> ProbeCoreAsync(
        RemoteSshEndpoint endpoint,
        RemotePrivateKeyMaterial privateKey,
        CancellationToken cancellationToken)
    {

        using var keyStream = privateKey.OpenReadStream();
        using var keyFile = new PrivateKeyFile(keyStream);
        var authentication = new PrivateKeyAuthenticationMethod(
            endpoint.Username,
            keyFile);
        var connectionInfo = new ConnectionInfo(
            endpoint.Host,
            endpoint.Port,
            endpoint.Username,
            authentication)
        {
            Timeout = RemoteSshConnectionOptions.DefaultConnectTimeout,
        };
        SshAlgorithmPolicy.ApplyForDiscovery(connectionInfo);

        using var client = new SftpClient(connectionInfo)
        {
            OperationTimeout = RemoteSshConnectionOptions.DefaultOperationTimeout,
        };
        string? algorithm = null;
        byte[]? rawHostKey = null;
        client.HostKeyReceived += (_, eventArgs) =>
        {
            if (!SshAlgorithmPolicy.IsAllowedHostKeyAlgorithm(
                    eventArgs.HostKeyName))
            {
                eventArgs.CanTrust = false;
                return;
            }

            algorithm = eventArgs.HostKeyName;
            rawHostKey = eventArgs.HostKey.ToArray();
            eventArgs.CanTrust = true;
        };

        try
        {
            await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
            if (!client.IsConnected || algorithm is null || rawHostKey is null)
            {
                throw new InvalidOperationException(
                    "The SSH server did not provide a usable host identity.");
            }

            var fingerprint =
                "SHA256:" +
                Convert.ToBase64String(SHA256.HashData(rawHostKey)).TrimEnd('=');
            return new SshConnectionProbeResult(
                endpoint,
                algorithm,
                fingerprint,
                Convert.ToBase64String(rawHostKey),
                AuthenticationSucceeded: true,
                SftpAvailable: true);
        }
        finally
        {
            if (client.IsConnected)
            {
                client.Disconnect();
            }

            if (rawHostKey is not null)
            {
                CryptographicOperations.ZeroMemory(rawHostKey);
            }
        }
    }
}
