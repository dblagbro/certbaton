using System.Security.Cryptography;
using System.Text.Json;
using CertBaton.Contracts;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class LiveCtlCommandLineTests
{
    private static readonly JsonSerializerOptions webJsonOptions =
        new(JsonSerializerDefaults.Web);

    [TestMethod]
    public async Task TargetEnrollReadsStrictNonSecretConfiguration()
    {
        var payload = CreateEnrollmentPayload();
        var path = Path.Combine(
            Path.GetTempPath(),
            $"certbaton-target-{Guid.CreateVersion7():N}.json");
        await File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize(payload, webJsonOptions));
        try
        {
            using var output = new StringWriter();
            using var error = new StringWriter();
            TargetEnrollmentPayload? observed = null;
            var responseTarget = CreateTargetSnapshot(payload);

            var exitCode = await CertBaton.Ctl.Program.RunAsync(
                ["target", "enroll", "--config", path, "--json"],
                output,
                error,
                enrollTargetAsync: candidate =>
                {
                    observed = candidate;
                    return Task.FromResult(
                        IpcResponse.Succeeded(Guid.NewGuid(), responseTarget));
                });

            Assert.AreEqual(0, exitCode);
            Assert.IsNotNull(observed);
            Assert.AreEqual(payload.EnrollmentId, observed.EnrollmentId);
            Assert.AreEqual(payload.CredentialReference, observed.CredentialReference);
            Assert.AreEqual(string.Empty, error.ToString());
            using var document = JsonDocument.Parse(output.ToString());
            Assert.AreEqual(
                payload.EnrollmentId,
                document.RootElement.GetProperty("targetId").GetGuid());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task TargetEnrollRejectsUnknownJsonWithoutContactingService()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"certbaton-target-{Guid.CreateVersion7():N}.json");
        await File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize(CreateEnrollmentPayload(), webJsonOptions)
                .TrimEnd('}') + ",\"unexpected\":true}");
        try
        {
            using var output = new StringWriter();
            using var error = new StringWriter();
            var contacted = false;

            var exitCode = await CertBaton.Ctl.Program.RunAsync(
                ["target", "enroll", "--config", path],
                output,
                error,
                enrollTargetAsync: _ =>
                {
                    contacted = true;
                    throw new InvalidOperationException();
                });

            Assert.AreEqual(2, exitCode);
            Assert.IsFalse(contacted);
            StringAssert.Contains(
                error.ToString(),
                "target configuration is not valid CertBaton JSON");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task RenewalStartGeneratesARequestIdentityAndReturnsOperation()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var targetId = Guid.CreateVersion7();
        var operationId = Guid.CreateVersion7();
        var observedKey = Guid.Empty;
        var operation = CreateQueuedOperation(operationId, targetId);

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            ["renewal", "start", "--target-id", targetId.ToString("D")],
            output,
            error,
            startRenewalAsync: (candidateTargetId, key) =>
            {
                Assert.AreEqual(targetId, candidateTargetId);
                observedKey = key;
                return Task.FromResult(
                    IpcResponse.Succeeded(Guid.NewGuid(), operation));
            });

        Assert.AreEqual(0, exitCode);
        Assert.AreNotEqual(Guid.Empty, observedKey);
        Assert.AreEqual(string.Empty, error.ToString());
        StringAssert.Contains(output.ToString(), operationId.ToString("D"));
    }

    [TestMethod]
    public async Task RenewalGetRequiresAnOperationIdentifier()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var contacted = false;

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            ["renewal", "get"],
            output,
            error,
            getRenewalAsync: _ =>
            {
                contacted = true;
                throw new InvalidOperationException();
            });

        Assert.AreEqual(2, exitCode);
        Assert.IsFalse(contacted);
        StringAssert.Contains(error.ToString(), "--operation-id is required");
    }

    private static TargetEnrollmentPayload CreateEnrollmentPayload()
    {
        var rawKey = RandomNumberGenerator.GetBytes(48);
        return new TargetEnrollmentPayload(
            Guid.CreateVersion7(),
            "Example target",
            ["www2.example.test"],
            "ssh.example.test",
            22,
            "certbaton",
            Guid.CreateVersion7(),
            "ssh-ed25519",
            "SHA256:" + Convert.ToBase64String(SHA256.HashData(rawKey)).TrimEnd('='),
            Convert.ToBase64String(rawKey),
            "/srv/www/challenges",
            "/srv/certbaton/incoming",
            "/srv/certbaton/releases/current/fullchain.pem",
            "/srv/certbaton/releases/current/privkey.pem",
            LiveContractValues.LetsEncryptStaging,
            "operator@example.test",
            true,
            true,
            20,
            720);
    }

    private static TargetSnapshot CreateTargetSnapshot(
        TargetEnrollmentPayload payload) =>
        new(
            payload.EnrollmentId,
            payload.DisplayName,
            payload.DnsNames,
            payload.Host,
            payload.Port,
            payload.Username,
            payload.HostKeyAlgorithm,
            payload.HostKeyFingerprintSha256,
            payload.CertificateAuthority,
            payload.AutoRenew,
            null,
            "ready");

    private static RenewalOperationSnapshot CreateQueuedOperation(
        Guid operationId,
        Guid targetId)
    {
        var now = DateTimeOffset.UtcNow;
        return new RenewalOperationSnapshot(
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
    }
}
