using System.Security.Cryptography;
using CertBaton.Application.Remote;

namespace CertBaton.Remote.Ssh.Tests;

[TestClass]
public sealed class SshHostKeyPinTests
{
    private const string Algorithm = "ssh-ed25519";

    [TestMethod]
    public void MatchesBindsHostPortAlgorithmFingerprintAndRawBlob()
    {
        var key = RandomNumberGenerator.GetBytes(64);
        var pin = CreatePin("host.example", 22, Algorithm, key, includeRawKey: true);
        var endpoint = RemoteSshEndpoint.Create("HOST.EXAMPLE.", 22, "deploy");

        Assert.IsTrue(pin.Matches(endpoint, Algorithm, key));
        Assert.IsFalse(pin.Matches(RemoteSshEndpoint.Create("other.example", 22, "deploy"), Algorithm, key));
        Assert.IsFalse(pin.Matches(RemoteSshEndpoint.Create("host.example", 2222, "deploy"), Algorithm, key));
        Assert.IsFalse(pin.Matches(endpoint, "ecdsa-sha2-nistp256", key));

        key[0] ^= 0xff;
        Assert.IsFalse(pin.Matches(endpoint, Algorithm, key));
    }

    [TestMethod]
    public void MatchesUsesFingerprintWhenRawBlobWasNotPersisted()
    {
        var key = RandomNumberGenerator.GetBytes(64);
        var pin = CreatePin("host.example", 22, Algorithm, key, includeRawKey: false);
        var endpoint = RemoteSshEndpoint.Create("host.example", 22, "deploy");

        Assert.IsTrue(pin.Matches(endpoint, Algorithm, key));
        Assert.IsFalse(pin.HasRawHostKey);
    }

    [TestMethod]
    public void CreateRejectsRawBlobThatDoesNotMatchFingerprint()
    {
        var key = RandomNumberGenerator.GetBytes(64);
        var otherKey = RandomNumberGenerator.GetBytes(64);
        var fingerprint = Fingerprint(key);

        Assert.Throws<ArgumentException>(() =>
            SshHostKeyPin.Create("host.example", 22, Algorithm, fingerprint, otherKey));
    }

    [TestMethod]
    [DataRow("ssh-rsa")]
    [DataRow("ssh-dss")]
    [DataRow("SSH-ED25519")]
    [DataRow("ssh-ed25519 ")]
    [DataRow("")]
    public void CreateRejectsWeakOrNonCanonicalAlgorithm(string algorithm)
    {
        var key = RandomNumberGenerator.GetBytes(64);

        Assert.Throws<ArgumentException>(() =>
            SshHostKeyPin.Create("host.example", 22, algorithm, Fingerprint(key), key));
    }

    [TestMethod]
    public void CreateRejectsPaddedFingerprint()
    {
        var key = RandomNumberGenerator.GetBytes(64);
        var padded = "SHA256:" + Convert.ToBase64String(SHA256.HashData(key));

        Assert.Throws<ArgumentException>(() =>
            SshHostKeyPin.Create("host.example", 22, Algorithm, padded, key));
    }

    [TestMethod]
    public void ExportRawHostKeyReturnsDefensiveCopy()
    {
        var key = RandomNumberGenerator.GetBytes(64);
        var pin = CreatePin("host.example", 22, Algorithm, key, includeRawKey: true);
        var firstExport = pin.ExportRawHostKey();
        Assert.IsNotNull(firstExport);
        firstExport[0] ^= 0xff;

        var secondExport = pin.ExportRawHostKey();

        CollectionAssert.AreEqual(key, secondExport);
    }

    internal static SshHostKeyPin CreatePin(
        string host,
        int port,
        string algorithm,
        byte[] key,
        bool includeRawKey = true) =>
        SshHostKeyPin.Create(
            host,
            port,
            algorithm,
            Fingerprint(key),
            includeRawKey ? key : ReadOnlySpan<byte>.Empty);

    private static string Fingerprint(byte[] key) =>
        "SHA256:" + Convert.ToBase64String(SHA256.HashData(key)).TrimEnd('=');
}
