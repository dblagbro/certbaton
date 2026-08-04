using System.Security.Cryptography;
using CertBaton.Application.Persistence;
using CertBaton.Contracts;
using CertBaton.Persistence.Sqlite;
using CertBaton.Service;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class LiveTargetCoordinatorTests
{
    private readonly List<string> testDirectories = [];

    [TestCleanup]
    public void Cleanup()
    {
        foreach (var directory in testDirectories)
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [TestMethod]
    public void EnrollmentIsAtomicAndRetryableByEnrollmentIdentifier()
    {
        var now = new DateTimeOffset(
            2026,
            7,
            31,
            18,
            0,
            0,
            TimeSpan.Zero);
        var store = CreateStore(now);
        var coordinator = new LiveTargetCoordinator(
            store,
            new FixedTimeProvider(now));
        var payload = CreateEnrollmentPayload();

        var first = coordinator.Enroll(payload, "S-1-5-32-544");
        var retry = coordinator.Enroll(payload, "S-1-5-32-544");
        var list = coordinator.List();

        Assert.AreEqual(payload.EnrollmentId, first.TargetId);
        Assert.AreEqual(first.TargetId, retry.TargetId);
        Assert.AreEqual(first.HostKeyFingerprintSha256, retry.HostKeyFingerprintSha256);
        Assert.HasCount(1, list.Targets);
        Assert.AreEqual(LiveContractValues.LetsEncryptStaging, first.CertificateAuthority);
        Assert.AreEqual("ready", first.Status);
    }

    [TestMethod]
    public void ReusedEnrollmentIdentityCannotChangePinnedHost()
    {
        var now = DateTimeOffset.UtcNow;
        var store = CreateStore(now);
        var coordinator = new LiveTargetCoordinator(
            store,
            new FixedTimeProvider(now));
        var payload = CreateEnrollmentPayload();
        _ = coordinator.Enroll(payload, "S-1-5-32-544");
        var changedRawKey = RandomNumberGenerator.GetBytes(48);
        var changed = payload with
        {
            HostKeyFingerprintSha256 =
                "SHA256:" +
                Convert.ToBase64String(SHA256.HashData(changedRawKey)).TrimEnd('='),
            HostKeyBase64 = Convert.ToBase64String(changedRawKey),
        };

        Assert.ThrowsExactly<ProductionEnrollmentConflictException>(
            () => coordinator.Enroll(changed, "S-1-5-32-544"));
    }

    private SqliteProductionStore CreateStore(DateTimeOffset initializedAtUtc)
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            $"certbaton-live-target-{Guid.CreateVersion7():N}");
        Directory.CreateDirectory(directory);
        testDirectories.Add(directory);
        var store = new SqliteProductionStore(
            Path.Combine(directory, "state.db"));
        store.Initialize(initializedAtUtc);
        return store;
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

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
