using System.Security.Cryptography;
using CertBaton.Application.Remote;

namespace CertBaton.Remote.Ssh.Tests;

[TestClass]
public sealed class RemoteConnectionOptionsTests
{
    [TestMethod]
    public void ConstructorAcceptsMatchingNormalizedEndpointAndBoundedValues()
    {
        var endpoint = RemoteSshEndpoint.Create("HOST.EXAMPLE.", 22, "deploy");
        var pin = CreatePin("host.example", 22);

        var options = new RemoteSshConnectionOptions(
            endpoint,
            pin,
            TimeSpan.FromSeconds(5),
            TimeSpan.FromMinutes(2),
            maximumTransferBytes: 1024,
            maximumHelperOutputBytes: 512);

        Assert.AreSame(endpoint, options.Endpoint);
        Assert.AreSame(pin, options.HostKeyPin);
        Assert.AreEqual(1024, options.MaximumTransferBytes);
        Assert.AreEqual(512, options.MaximumHelperOutputBytes);
    }

    [TestMethod]
    public void ConstructorRejectsPinForDifferentHostOrPort()
    {
        var endpoint = RemoteSshEndpoint.Create("host.example", 22, "deploy");

        Assert.Throws<ArgumentException>(() => new RemoteSshConnectionOptions(endpoint, CreatePin("other.example", 22)));
        Assert.Throws<ArgumentException>(() => new RemoteSshConnectionOptions(endpoint, CreatePin("host.example", 2222)));
    }

    [TestMethod]
    [DataRow(0L)]
    [DataRow(RemoteSshConnectionOptions.AbsoluteMaximumTransferBytes + 1)]
    public void ConstructorRejectsTransferLimitOutsidePolicy(long limit)
    {
        var endpoint = RemoteSshEndpoint.Create("host.example", 22, "deploy");

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new RemoteSshConnectionOptions(endpoint, CreatePin("host.example", 22), maximumTransferBytes: limit));
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(RemoteSshConnectionOptions.AbsoluteMaximumHelperOutputBytes + 1)]
    public void ConstructorRejectsHelperLimitOutsidePolicy(int limit)
    {
        var endpoint = RemoteSshEndpoint.Create("host.example", 22, "deploy");

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new RemoteSshConnectionOptions(endpoint, CreatePin("host.example", 22), maximumHelperOutputBytes: limit));
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(301)]
    public void ConstructorRejectsTimeoutOutsidePolicy(int seconds)
    {
        var endpoint = RemoteSshEndpoint.Create("host.example", 22, "deploy");

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new RemoteSshConnectionOptions(endpoint, CreatePin("host.example", 22), connectTimeout: TimeSpan.FromSeconds(seconds)));
    }

    private static SshHostKeyPin CreatePin(string host, int port)
    {
        var key = RandomNumberGenerator.GetBytes(64);
        return SshHostKeyPinTests.CreatePin(host, port, "ssh-ed25519", key);
    }
}
