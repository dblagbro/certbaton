using CertBaton.Application.Remote;
using Renci.SshNet;

namespace CertBaton.Remote.Ssh;

public sealed class SshNetSessionFactory : IRemoteSshSessionFactory
{
    public async ValueTask<IRemoteSshSession> ConnectAsync(
        RemoteSshConnectionOptions options,
        RemotePrivateKeyMaterial privateKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(privateKey);

        var sftpKeyStream = privateKey.OpenReadStream();
        var sshKeyStream = privateKey.OpenReadStream();
        PrivateKeyFile? sftpKeyFile = null;
        PrivateKeyFile? sshKeyFile = null;
        SftpClient? sftpClient = null;
        SshClient? sshClient = null;

        try
        {
            sftpKeyFile = new PrivateKeyFile(sftpKeyStream);
            sshKeyFile = new PrivateKeyFile(sshKeyStream);

            var sftpConnection = CreateConnectionInfo(options, sftpKeyFile);
            var sshConnection = CreateConnectionInfo(options, sshKeyFile);
            sftpClient = new SftpClient(sftpConnection)
            {
                OperationTimeout = options.OperationTimeout,
            };
            sshClient = new SshClient(sshConnection);

            var sftpVerifier = new SshHostKeyVerifier(options.Endpoint, options.HostKeyPin);
            var sshVerifier = new SshHostKeyVerifier(options.Endpoint, options.HostKeyPin);
            sftpClient.HostKeyReceived += sftpVerifier.Handle;
            sshClient.HostKeyReceived += sshVerifier.Handle;

            try
            {
                await sftpClient.ConnectAsync(cancellationToken).ConfigureAwait(false);
                await sshClient.ConnectAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (sftpVerifier.Rejected || sshVerifier.Rejected)
            {
                throw new SshHostKeyPinMismatchException(options.Endpoint, exception);
            }

            return new SshNetSession(
                options,
                sftpClient,
                sshClient,
                sftpKeyFile,
                sshKeyFile,
                sftpKeyStream,
                sshKeyStream);
        }
        catch
        {
            sshClient?.Dispose();
            sftpClient?.Dispose();
            sshKeyFile?.Dispose();
            sftpKeyFile?.Dispose();
            sshKeyStream.Dispose();
            sftpKeyStream.Dispose();
            throw;
        }
    }

    private static ConnectionInfo CreateConnectionInfo(RemoteSshConnectionOptions options, PrivateKeyFile privateKeyFile)
    {
        var endpoint = options.Endpoint;
        var authentication = new PrivateKeyAuthenticationMethod(endpoint.Username, privateKeyFile);
        var connectionInfo = new ConnectionInfo(endpoint.Host, endpoint.Port, endpoint.Username, authentication)
        {
            Timeout = options.ConnectTimeout,
        };
        SshAlgorithmPolicy.Apply(connectionInfo, options.HostKeyPin);
        return connectionInfo;
    }
}
