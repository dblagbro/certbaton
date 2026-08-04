using System.Security.Cryptography;
using CertBaton.Application.Remote;
using Renci.SshNet;

namespace CertBaton.Remote.Ssh.Tests;

[TestClass]
public sealed class SshAlgorithmPolicyTests
{
    [TestMethod]
    public void DiscoveryKeepsOnlyApprovedModernHostKeyAlgorithms()
    {
        var connectionInfo = new ConnectionInfo(
            "host.example",
            22,
            "deploy",
            new NoneAuthenticationMethod("deploy"));

        SshAlgorithmPolicy.ApplyForDiscovery(connectionInfo);

        Assert.IsGreaterThan(0, connectionInfo.HostKeyAlgorithms.Count);
        Assert.IsTrue(
            connectionInfo.HostKeyAlgorithms.Keys.All(
                SshAlgorithmPolicy.IsAllowedHostKeyAlgorithm));
        Assert.IsFalse(connectionInfo.HostKeyAlgorithms.ContainsKey("ssh-rsa"));
        Assert.IsFalse(connectionInfo.HostKeyAlgorithms.ContainsKey("ssh-dss"));
    }

    [TestMethod]
    public void ApplyRemovesWeakAlgorithmsAndNarrowsHostKeyToPin()
    {
        var key = RandomNumberGenerator.GetBytes(64);
        var pin = SshHostKeyPinTests.CreatePin("host.example", 22, "ssh-ed25519", key);
        var connectionInfo = new ConnectionInfo(
            "host.example",
            22,
            "deploy",
            new NoneAuthenticationMethod("deploy"));

        SshAlgorithmPolicy.Apply(connectionInfo, pin);

        Assert.AreEqual(1, connectionInfo.HostKeyAlgorithms.Count);
        Assert.IsTrue(connectionInfo.HostKeyAlgorithms.ContainsKey("ssh-ed25519"));
        Assert.IsFalse(connectionInfo.KeyExchangeAlgorithms.Keys.Any(name =>
            name.Contains("sha1", StringComparison.OrdinalIgnoreCase)
            || name.Contains("group1", StringComparison.OrdinalIgnoreCase)));
        Assert.IsFalse(connectionInfo.Encryptions.Keys.Any(name =>
            name.Contains("-cbc", StringComparison.OrdinalIgnoreCase)
            || name.Contains("3des", StringComparison.OrdinalIgnoreCase)
            || name.Contains("arcfour", StringComparison.OrdinalIgnoreCase)));
        Assert.IsFalse(connectionInfo.HmacAlgorithms.Keys.Any(name =>
            name.Contains("md5", StringComparison.OrdinalIgnoreCase)
            || name.Contains("sha1", StringComparison.OrdinalIgnoreCase)
            || name.Contains("ripemd", StringComparison.OrdinalIgnoreCase)));
    }
}
