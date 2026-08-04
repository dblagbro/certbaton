using CertBaton.Application.Remote;

namespace CertBaton.Remote.Ssh.Tests;

[TestClass]
public sealed class RemoteSshEndpointTests
{
    [TestMethod]
    public void CreateNormalizesDnsNameAndTrailingDot()
    {
        var endpoint = RemoteSshEndpoint.Create("WWW.Example.COM.", 22, "deploy-user");

        Assert.AreEqual("www.example.com", endpoint.Host);
        Assert.AreEqual(22, endpoint.Port);
        Assert.AreEqual("deploy-user", endpoint.Username);
    }

    [TestMethod]
    public void CreateNormalizesInternationalDnsNameToAscii()
    {
        var endpoint = RemoteSshEndpoint.Create("bücher.example", 2222, "deploy");

        Assert.AreEqual("xn--bcher-kva.example", endpoint.Host);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow(" example.com")]
    [DataRow("example.com ")]
    [DataRow("https://example.com")]
    [DataRow("bad_label.example")]
    [DataRow("-bad.example")]
    [DataRow("bad-.example")]
    public void CreateRejectsAmbiguousOrInvalidHosts(string host)
    {
        Assert.Throws<ArgumentException>(() => RemoteSshEndpoint.Create(host, 22, "deploy"));
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(65536)]
    public void CreateRejectsInvalidPort(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => RemoteSshEndpoint.Create("example.com", port, "deploy"));
    }

    [TestMethod]
    [DataRow("")]
    [DataRow(" deploy")]
    [DataRow("deploy user")]
    [DataRow("deploy;id")]
    [DataRow("deploy/root")]
    public void CreateRejectsUnsafeUsername(string username)
    {
        Assert.Throws<ArgumentException>(() => RemoteSshEndpoint.Create("example.com", 22, username));
    }
}
