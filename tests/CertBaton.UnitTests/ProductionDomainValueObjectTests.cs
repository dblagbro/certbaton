using System.Security.Cryptography;
using System.Text;
using CertBaton.Domain.Connections;
using CertBaton.Domain.Deployments;
using CertBaton.Domain.Operations;
using CertBaton.Domain.Scheduling;
using CertBaton.Domain.Targets;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class ProductionDomainValueObjectTests
{
    private static readonly DateTimeOffset testStart =
        new(2026, 7, 31, 12, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void GeneratedProductionIdentifiersUseUuidVersionSeven()
    {
        Assert.AreEqual(7, ConnectionId.Create().Value.Version);
        Assert.AreEqual(7, TargetId.Create().Value.Version);
        Assert.AreEqual(7, DeploymentPlanId.Create().Value.Version);
        Assert.AreEqual(7, OperationId.Create().Value.Version);
        Assert.AreEqual(7, OperationIntentId.Create().Value.Version);
        Assert.AreEqual(7, RenewalPolicyId.Create().Value.Version);
        Assert.AreEqual(7, AcmeAccountId.Create().Value.Version);
        Assert.AreEqual(7, EnrollmentId.Create().Value.Version);
        Assert.AreEqual(7, CertificateArtifactId.Create().Value.Version);
    }

    [TestMethod]
    public void NetworkNamesAreCanonicalAndUnsafeNamesAreRejected()
    {
        var endpoint = new ConnectionEndpoint("SSH.Example.COM.", 2222);
        var dnsName = new TargetDnsName("BÜCHER.Example.");

        Assert.AreEqual("ssh.example.com", endpoint.Host);
        Assert.AreEqual(2222, endpoint.Port);
        Assert.AreEqual("xn--bcher-kva.example", dnsName.Value);
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new TargetDnsName("*.example.com"));
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new ConnectionEndpoint("host name", 22));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = new ConnectionEndpoint("example.com", 0));
    }

    [TestMethod]
    public void RemotePathsRejectTraversalAndAmbiguousSeparators()
    {
        Assert.AreEqual(
            "/etc/letsencrypt/live/example/fullchain.pem",
            new RemotePath("/etc/letsencrypt/live/example/fullchain.pem").Value);
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new RemotePath("../../etc/passwd"));
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new RemotePath("/srv/www/../secrets"));
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new RemotePath("/srv//www"));
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new RemotePath(@"C:\certs\site.pem"));
    }

    [TestMethod]
    public void SchedulingAndEvidenceValuesEnforceTheirBounds()
    {
        var targetId = new TargetId(
            Guid.Parse("1e9886db-79d9-4d96-bd97-8c20353da882"));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = new RenewalPolicy(
                RenewalPolicyId.Create(),
                targetId,
                renewBeforeDays: 0,
                checkIntervalMinutes: 60,
                enabled: true,
                nextDueAtUtc: null,
                testStart,
                testStart));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = new RenewalPolicy(
                RenewalPolicyId.Create(),
                targetId,
                renewBeforeDays: 30,
                checkIntervalMinutes: 10,
                enabled: true,
                nextDueAtUtc: null,
                testStart,
                testStart));
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new OperationEvidence(
                OperationId.Create(),
                sequence: 1,
                OperationEvidenceKind.Verification,
                stage: "must-not-be-present",
                OperationEvidenceOutcome.Succeeded,
                testStart,
                "verification.ok",
                "Public verification succeeded."));
    }

    [TestMethod]
    public void SshHostKeyEnrollmentBindsAlgorithmFingerprintAndRawKey()
    {
        var rawHostKey = Encoding.UTF8.GetBytes("public-host-key-fixture");
        var fingerprint =
            "SHA256:" +
            Convert.ToBase64String(SHA256.HashData(rawHostKey)).TrimEnd('=');
        var profile = new ConnectionProfile(
            ConnectionId.Create(),
            "SSH host",
            new ConnectionEndpoint("ssh.example.com"),
            "deploy",
            "vault://connections/ssh-host",
            "ssh-ed25519",
            fingerprint,
            testStart,
            testStart,
            enabled: true,
            rawHostKey);

        Assert.AreEqual("ssh-ed25519", profile.HostKeyAlgorithm);
        CollectionAssert.AreEqual(rawHostKey, profile.ExportRawHostKey());
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new ConnectionProfile(
                ConnectionId.Create(),
                "Fingerprint only",
                new ConnectionEndpoint("ssh.example.com"),
                "deploy",
                "vault://connections/fingerprint-only",
                hostKeyAlgorithm: null,
                fingerprint,
                testStart,
                testStart,
                enabled: true));
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new ConnectionProfile(
                ConnectionId.Create(),
                "Mismatched key",
                new ConnectionEndpoint("ssh.example.com"),
                "deploy",
                "vault://connections/mismatch",
                "ssh-ed25519",
                fingerprint,
                testStart,
                testStart,
                enabled: true,
                Encoding.UTF8.GetBytes("different-public-key")));
    }

    [TestMethod]
    public void IssuanceProfileRequiresHttpsAndAuditableTermsAcceptance()
    {
        var targetId = TargetId.Create();
        var contact = new AcmeContactUri("operator@example.com");
        Assert.AreEqual("mailto:operator@example.com", contact.Value);
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new TargetIssuanceProfile(
                targetId,
                new Uri("http://acme.example/directory"),
                contact,
                termsAccepted: true,
                testStart,
                "vault://acme/account-key",
                accountUri: null,
                testStart,
                testStart));
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new TargetIssuanceProfile(
                targetId,
                new Uri("https://acme.example/directory"),
                contact,
                termsAccepted: false,
                testStart,
                "vault://acme/account-key",
                accountUri: null,
                testStart,
                testStart));
    }

    [TestMethod]
    public void CertificateDigestsAreCanonicalAndPrivateKeysRemainReferences()
    {
        Assert.AreEqual(
            new string('A', 64),
            new Sha256Digest(new string('a', 64)).Value);
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new Sha256Digest("not-a-sha256-digest"));
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new CertificateArtifact(
                CertificateArtifactId.Create(),
                OperationId.Create(),
                new Sha256Digest(new string('A', 64)),
                new Sha256Digest(new string('B', 64)),
                "vault://certificates/private-key",
                testStart.AddDays(1),
                testStart,
                CertificateArtifactStatus.Issued,
                testStart));
    }
}
