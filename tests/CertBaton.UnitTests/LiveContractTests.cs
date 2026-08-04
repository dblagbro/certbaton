using System.Security.Cryptography;
using CertBaton.Contracts;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class LiveContractTests
{
    [TestMethod]
    public void EnrollmentFactoryCreatesStrictMethodPayload()
    {
        var payload = CreateEnrollmentPayload();

        var request = IpcRequest.CreateTargetEnrollment(
            TimeProvider.System,
            payload);

        Assert.AreEqual(IpcProtocol.TargetEnrollMethod, request.Method);
        Assert.AreSame(payload, request.TargetEnrollmentPayload);
        Assert.IsTrue(request.TryValidateMethodPayload(out var error), error);
    }

    [TestMethod]
    public void EnrollmentRejectsRawHostKeyFingerprintMismatch()
    {
        var payload = CreateEnrollmentPayload() with
        {
            HostKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)),
        };

        Assert.IsFalse(payload.TryValidate(out _));
    }

    [TestMethod]
    public void EnrollmentRejectsWildcardAndPathTraversal()
    {
        var wildcard = CreateEnrollmentPayload() with
        {
            DnsNames = ["*.example.test"],
        };
        var traversal = CreateEnrollmentPayload() with
        {
            ChallengeWebroot = "/srv/www/../private",
        };

        Assert.IsFalse(wildcard.TryValidate(out _));
        Assert.IsFalse(traversal.TryValidate(out _));
    }

    [TestMethod]
    public void EnrollmentRejectsAnArbitraryAcmeDirectorySelection()
    {
        var payload = CreateEnrollmentPayload() with
        {
            CertificateAuthority = "https://internal.example/acme",
        };

        Assert.IsFalse(payload.TryValidate(out _));
    }

    [TestMethod]
    public void RenewalFactoriesAndResultsAreMethodSpecific()
    {
        var targetId = Guid.CreateVersion7();
        var operationId = Guid.CreateVersion7();
        var start = IpcRequest.CreateRenewalStart(
            TimeProvider.System,
            new RenewalStartPayload(targetId, Guid.CreateVersion7()));
        var get = IpcRequest.CreateRenewalGet(
            TimeProvider.System,
            new RenewalQueryPayload(operationId));
        var now = DateTimeOffset.UtcNow;
        var operation = new RenewalOperationSnapshot(
            operationId,
            targetId,
            "queued",
            now,
            now,
            null,
            null,
            null,
            false,
            false,
            []);

        var startResponse = IpcResponse.Succeeded(start.RequestId, operation);
        var getResponse = IpcResponse.Succeeded(get.RequestId, operation);

        Assert.IsTrue(start.TryValidateMethodPayload(out _));
        Assert.IsTrue(get.TryValidateMethodPayload(out _));
        Assert.IsTrue(
            startResponse.TryValidateForMethod(start.Method, out var startError),
            startError);
        Assert.IsTrue(
            getResponse.TryValidateForMethod(get.Method, out var getError),
            getError);
        Assert.IsFalse(
            startResponse.TryValidateForMethod(
                IpcProtocol.TargetListMethod,
                out _));
    }

    [TestMethod]
    public void SuccessCannotOmitFinalVerificationOrCleanup()
    {
        var now = DateTimeOffset.UtcNow;
        var snapshot = new RenewalOperationSnapshot(
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            "succeeded",
            now,
            now.AddMinutes(1),
            now.AddMinutes(1),
            null,
            new string('A', 64),
            PublicTlsVerified: false,
            ChallengeCleanupVerified: true,
            []);

        Assert.IsFalse(snapshot.TryValidate(out _));
    }

    private static TargetEnrollmentPayload CreateEnrollmentPayload()
    {
        var hostKey = RandomNumberGenerator.GetBytes(48);
        var fingerprint = SHA256.HashData(hostKey);
        return new TargetEnrollmentPayload(
            Guid.CreateVersion7(),
            "Example target",
            ["www2.example.test"],
            "ssh.example.test",
            22,
            "certbaton",
            Guid.CreateVersion7(),
            "ssh-ed25519",
            "SHA256:" + Convert.ToBase64String(fingerprint).TrimEnd('='),
            Convert.ToBase64String(hostKey),
            "/srv/www/challenges",
            "/srv/certbaton/incoming",
            "/srv/certbaton/releases/current/fullchain.pem",
            "/srv/certbaton/releases/current/privkey.pem",
            LiveContractValues.LetsEncryptStaging,
            "operator@example.test",
            TermsOfServiceAgreed: true,
            AutoRenew: true,
            RenewBeforeDays: 20,
            CheckIntervalMinutes: 720);
    }
}
