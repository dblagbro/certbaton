using System.Security.Cryptography;
using CertBaton.Application.Remote;

namespace CertBaton.Remote.Ssh.Tests;

[TestClass]
public sealed class ReadOnlySshProbeTests
{
    [TestMethod]
    [TestCategory("LiveReadOnly")]
    public async Task DiscoveryAuthenticatesAndReturnsExpectedServerIdentity()
    {
        var settings = ReadSettings();
        if (settings is null)
        {
            Assert.Inconclusive(
                "Set the CERTBATON_LIVE_SSH_* environment variables to opt in to the read-only SSH probe.");
            return;
        }

        var keyBytes = await File.ReadAllBytesAsync(settings.KeyPath)
            .ConfigureAwait(false);
        try
        {
            using var privateKey = new RemotePrivateKeyMaterial(keyBytes);
            var endpoint = RemoteSshEndpoint.Create(
                settings.Host,
                settings.Port,
                settings.Username);
            var probe = new SshNetConnectionProbe();

            var result = await probe.ProbeAsync(
                endpoint,
                privateKey,
                TestContext.CancellationToken);

            Assert.IsTrue(result.AuthenticationSucceeded);
            Assert.IsTrue(result.SftpAvailable);
            Assert.AreEqual(settings.HostKeyAlgorithm, result.HostKeyAlgorithm);
            Assert.AreEqual(
                settings.HostKeyFingerprint,
                result.HostKeyFingerprintSha256);
            Assert.IsNotEmpty(result.HostKeyBase64);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    [TestMethod]
    [TestCategory("LiveReadOnly")]
    public async Task EnrolledEndpointCanConnectAndStatConfiguredFile()
    {
        var settings = ReadSettings();
        if (settings is null)
        {
            Assert.Inconclusive(
                "Set the CERTBATON_LIVE_SSH_* environment variables to opt in to the read-only SSH probe.");
            return;
        }

        var keyBytes = await File.ReadAllBytesAsync(settings.KeyPath).ConfigureAwait(false);
        try
        {
            using var privateKey = new RemotePrivateKeyMaterial(keyBytes);
            var endpoint = RemoteSshEndpoint.Create(settings.Host, settings.Port, settings.Username);
            var pin = SshHostKeyPin.Create(
                settings.Host,
                settings.Port,
                settings.HostKeyAlgorithm,
                settings.HostKeyFingerprint);
            var options = new RemoteSshConnectionOptions(
                endpoint,
                pin,
                connectTimeout: TimeSpan.FromSeconds(20),
                operationTimeout: TimeSpan.FromSeconds(20));
            var factory = new SshNetSessionFactory();

            await using var session = await factory.ConnectAsync(options, privateKey, TestContext.CancellationToken);
            var exists = await session.FileExistsAsync(
                RemotePosixPath.Parse(settings.ProbePath),
                TestContext.CancellationToken);

            Assert.IsTrue(exists, "The configured read-only probe file was not visible over SFTP.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    [TestMethod]
    [TestCategory("LiveReadOnly")]
    public async Task IncorrectHostKeyPinFailsClosed()
    {
        var settings = ReadSettings();
        if (settings is null)
        {
            Assert.Inconclusive(
                "Set the CERTBATON_LIVE_SSH_* environment variables to opt in to the read-only SSH probe.");
            return;
        }

        var keyBytes = await File.ReadAllBytesAsync(settings.KeyPath).ConfigureAwait(false);
        try
        {
            using var privateKey = new RemotePrivateKeyMaterial(keyBytes);
            var endpoint = RemoteSshEndpoint.Create(settings.Host, settings.Port, settings.Username);
            var deliberatelyIncorrectFingerprint = "SHA256:" + Convert.ToBase64String(new byte[32]).TrimEnd('=');
            var pin = SshHostKeyPin.Create(
                settings.Host,
                settings.Port,
                settings.HostKeyAlgorithm,
                deliberatelyIncorrectFingerprint);
            var options = new RemoteSshConnectionOptions(
                endpoint,
                pin,
                connectTimeout: TimeSpan.FromSeconds(20),
                operationTimeout: TimeSpan.FromSeconds(20));
            var factory = new SshNetSessionFactory();

            await Assert.ThrowsExactlyAsync<SshHostKeyPinMismatchException>(async () =>
            {
                await using var unexpectedSession = await factory.ConnectAsync(
                    options,
                    privateKey,
                    TestContext.CancellationToken);
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    public TestContext TestContext { get; set; } = null!;

    private static LiveSettings? ReadSettings()
    {
        var host = Environment.GetEnvironmentVariable("CERTBATON_LIVE_SSH_HOST");
        var portText = Environment.GetEnvironmentVariable("CERTBATON_LIVE_SSH_PORT");
        var username = Environment.GetEnvironmentVariable("CERTBATON_LIVE_SSH_USERNAME");
        var algorithm = Environment.GetEnvironmentVariable("CERTBATON_LIVE_SSH_HOST_KEY_ALGORITHM");
        var fingerprint = Environment.GetEnvironmentVariable("CERTBATON_LIVE_SSH_HOST_KEY_SHA256");
        var keyPath = Environment.GetEnvironmentVariable("CERTBATON_LIVE_SSH_KEY_PATH");
        var probePath = Environment.GetEnvironmentVariable("CERTBATON_LIVE_SSH_PROBE_PATH");

        if (string.IsNullOrEmpty(host)
            || string.IsNullOrEmpty(portText)
            || string.IsNullOrEmpty(username)
            || string.IsNullOrEmpty(algorithm)
            || string.IsNullOrEmpty(fingerprint)
            || string.IsNullOrEmpty(keyPath)
            || string.IsNullOrEmpty(probePath))
        {
            return null;
        }

        if (!int.TryParse(portText, out var port))
        {
            throw new InvalidOperationException("CERTBATON_LIVE_SSH_PORT must be an integer.");
        }

        return new LiveSettings(host, port, username, algorithm, fingerprint, keyPath, probePath);
    }

    private sealed record LiveSettings(
        string Host,
        int Port,
        string Username,
        string HostKeyAlgorithm,
        string HostKeyFingerprint,
        string KeyPath,
        string ProbePath);
}
