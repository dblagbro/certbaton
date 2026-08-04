using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using CertBaton.Application.Security;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;
using CertBaton.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class VaultProbeTests
{
    [TestMethod]
    public void ProbeRoundTripsAndRemovesOneTimeCanary()
    {
        var vault = new MemorySecretVault();
        var time = new DateTimeOffset(
            2026,
            7,
            31,
            16,
            0,
            0,
            TimeSpan.Zero);
        var probe = new VaultProbe(
            vault,
            new FixedTimeProvider(time));

        var result = probe.Run();

        Assert.AreEqual("healthy", result.Status);
        Assert.IsTrue(result.RoundTripVerified);
        Assert.IsTrue(result.TemporaryRecordRemoved);
        Assert.AreEqual(time, result.CheckedAtUtc);
        Assert.AreEqual(0, vault.Count);
    }

    [TestMethod]
    public async Task InstalledServiceRequiresAdministratorForVaultProbe()
    {
        var options = new IpcServerOptions
        {
            PipeName = $"CertBaton.UnitTests.{Guid.NewGuid():N}",
            SecurityProfile = PipeServerSecurityProfile.InstalledService,
        };
        var probe = new CountingVaultProbe();
        var timeProvider = new FixedTimeProvider(DateTimeOffset.UtcNow);
        var worker = new IpcWorker(
            new CertBatonPipeServer(options, timeProvider: timeProvider),
            new NullSimulationCoordinator(),
            new SimulationAccessPolicy(options),
            NullLogger<IpcWorker>.Instance,
            timeProvider,
            probe);
        var request = IpcRequest.CreateVaultProbe(timeProvider);

        var denied = await worker.HandleRequestAsync(
            request,
            CreateIdentity(isAdministrator: false),
            CancellationToken.None);
        var allowed = await worker.HandleRequestAsync(
            request with { RequestId = Guid.NewGuid() },
            CreateIdentity(isAdministrator: true),
            CancellationToken.None);

        Assert.IsFalse(denied.Success);
        Assert.AreEqual("vault_probe_forbidden", denied.Error?.Code);
        Assert.IsTrue(allowed.Success);
        Assert.AreEqual("healthy", allowed.Result?.VaultProbe?.Status);
        Assert.AreEqual(1, probe.Count);
    }

    [TestMethod]
    public async Task CliWritesVaultProbeAsJson()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var snapshot = new VaultProbeSnapshot(
            "healthy",
            true,
            true,
            DateTimeOffset.UtcNow);

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            ["vault", "probe", "--json"],
            output,
            error,
            probeVaultAsync: () => Task.FromResult(
                IpcResponse.Succeeded(Guid.NewGuid(), snapshot)));

        Assert.AreEqual(0, exitCode);
        Assert.AreEqual(string.Empty, error.ToString());
        using var document = JsonDocument.Parse(output.ToString());
        Assert.AreEqual(
            "healthy",
            document.RootElement.GetProperty("status").GetString());
        Assert.IsTrue(
            document.RootElement.GetProperty("roundTripVerified").GetBoolean());
    }

    [TestMethod]
    public void CredentialImporterStoresKeyUnderOpaqueReference()
    {
        var vault = new MemorySecretVault();
        var storedAt = DateTimeOffset.UtcNow;
        var importer = new CredentialImporter(
            vault,
            new FixedTimeProvider(storedAt));
        var privateKey =
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-only\n-----END OPENSSH PRIVATE KEY-----\n"u8
            .ToArray();
        try
        {
            var result = importer.ImportSshPrivateKey(privateKey);

            Assert.AreNotEqual(Guid.Empty, result.CredentialReference);
            Assert.AreEqual(
                CredentialContractValues.SshPrivateKeyKind,
                result.Kind);
            Assert.AreEqual(storedAt, result.StoredAtUtc);
            var recovered = vault.Read(
                new SecretReference(result.CredentialReference));
            try
            {
                CollectionAssert.AreEqual(privateKey, recovered);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(recovered);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    [TestMethod]
    public async Task CliImportsKeyFromFileAndClearsItsWorkingBuffer()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"certbaton-key-{Guid.CreateVersion7():N}");
        var fileBytes =
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-only\n-----END OPENSSH PRIVATE KEY-----\n"u8
            .ToArray();
        await File.WriteAllBytesAsync(path, fileBytes);
        ReadOnlyMemory<byte> received = default;
        try
        {
            using var output = new StringWriter();
            using var error = new StringWriter();
            var snapshot = new CredentialImportSnapshot(
                Guid.CreateVersion7(),
                CredentialContractValues.SshPrivateKeyKind,
                DateTimeOffset.UtcNow);

            var exitCode = await CertBaton.Ctl.Program.RunAsync(
                ["credential", "import-ssh-key", "--file", path, "--json"],
                output,
                error,
                importSshPrivateKeyAsync: privateKey =>
                {
                    received = privateKey;
                    CollectionAssert.AreEqual(
                        fileBytes,
                        privateKey.ToArray());
                    return Task.FromResult(
                        IpcResponse.Succeeded(Guid.NewGuid(), snapshot));
                });

            Assert.AreEqual(0, exitCode);
            Assert.IsTrue(
                received.Span.ToArray().All(static value => value == 0),
                "The CLI did not clear its private-key working buffer.");
            Assert.IsFalse(
                output.ToString().Contains(
                    "BEGIN OPENSSH PRIVATE KEY",
                    StringComparison.Ordinal));
            Assert.AreEqual(string.Empty, error.ToString());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
            File.Delete(path);
        }
    }

    private static PipeClientIdentity CreateIdentity(bool isAdministrator) =>
        new(
            isAdministrator ? "S-1-5-32-544" : "S-1-5-32-545",
            isAdministrator,
            TokenImpersonationLevel.Identification);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class CountingVaultProbe : IVaultProbe
    {
        private int count;

        public int Count => Volatile.Read(ref count);

        public VaultProbeSnapshot Run()
        {
            Interlocked.Increment(ref count);
            return new VaultProbeSnapshot(
                "healthy",
                true,
                true,
                DateTimeOffset.UtcNow);
        }
    }

    private sealed class NullSimulationCoordinator : ISimulationCoordinator
    {
        public CertBaton.Application.Simulation.Persistence.SimulationJobDetails?
            Latest => null;

        public Task<CertBaton.Application.Simulation.Persistence.SimulationJobDetails>
            StartAsync(
                Guid idempotencyKey,
                CertBaton.Domain.Renewals.RenewalStage? failureStage,
                CancellationToken cancellationToken) =>
            throw new InvalidOperationException(
                "The vault probe test must not start a simulation.");
    }

    private sealed class MemorySecretVault : ISecretVault
    {
        private readonly Dictionary<Guid, byte[]> records = [];

        public int Count => records.Count;

        public bool Contains(SecretReference reference) =>
            records.ContainsKey(reference.Value);

        public void Store(
            SecretReference reference,
            ReadOnlySpan<byte> secret,
            bool replace = false)
        {
            if (!replace && records.ContainsKey(reference.Value))
            {
                throw new IOException("The secret already exists.");
            }

            records[reference.Value] = secret.ToArray();
        }

        public void ImportProtected(
            SecretReference reference,
            ReadOnlySpan<byte> protectedSecret,
            bool replace = false) =>
            Store(reference, protectedSecret, replace);

        public byte[] Read(SecretReference reference) =>
            records[reference.Value].ToArray();

        public bool Delete(SecretReference reference)
        {
            if (!records.Remove(reference.Value, out var secret))
            {
                return false;
            }

            CryptographicOperations.ZeroMemory(secret);
            return true;
        }
    }
}
