using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using CertBaton.Application.Acme;
using CertBaton.Application.Security;
using CertBaton.Domain.Targets;
using CertBaton.Persistence.Sqlite;
using CertBaton.Service;

namespace CertBaton.UnitTests;

[TestClass]
[DoNotParallelize]
public sealed class VaultBackedAcmeAccountStoreTests
{
    private static readonly DateTimeOffset testTime =
        new(2026, 7, 31, 16, 0, 0, TimeSpan.Zero);
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
    public async Task SaveAndLoadRoundTripPreservesAccountIdentityAndKey()
    {
        var store = CreateStore();
        using var vault = new MemorySecretVault();
        var subject = CreateSubject(store, vault);
        var reference = new SecretReference(
            Guid.Parse("a7f70c0b-5922-49bf-a716-d5a7da868f08"));
        var directoryUri = new Uri("https://acme.example.test/directory");
        var accountUri = new Uri("https://acme.example.test/account/101");
        var accountKey = CreateSyntheticKey("round-trip-key");

        using (var account = new AcmeAccount(directoryUri, accountUri, accountKey))
        {
            await subject.SaveAsync(account, reference, CancellationToken.None);
        }

        using var loaded = await subject.LoadAsync(
            directoryUri,
            reference,
            CancellationToken.None);
        AssertAccount(loaded, directoryUri, accountUri, accountKey);
        var record = store.FindAcmeAccount(directoryUri, reference.ToString());
        Assert.IsNotNull(record);
        Assert.AreEqual(AcmeAccountStatus.Valid, record.Status);
        Assert.AreEqual(accountUri, record.AccountUri);
    }

    [TestMethod]
    public async Task AccountsInSameDirectoryRemainBoundToExactSecretReferences()
    {
        var store = CreateStore();
        using var vault = new MemorySecretVault();
        var subject = CreateSubject(store, vault);
        var directoryUri = new Uri("https://acme.example.test/directory");
        var firstReference = new SecretReference(
            Guid.Parse("66e724a4-fd3f-4cb0-b04e-4eb6ca9034cb"));
        var secondReference = new SecretReference(
            Guid.Parse("7f2db5ba-541a-4be1-8c6d-6132d2ab5fb4"));
        var firstAccountUri = new Uri("https://acme.example.test/account/201");
        var secondAccountUri = new Uri("https://acme.example.test/account/202");
        var firstKey = CreateSyntheticKey("first-shared-directory-key");
        var secondKey = CreateSyntheticKey("second-shared-directory-key");

        using (var first = new AcmeAccount(
                   directoryUri,
                   firstAccountUri,
                   firstKey))
        using (var second = new AcmeAccount(
                   directoryUri,
                   secondAccountUri,
                   secondKey))
        {
            await subject.SaveAsync(first, firstReference, CancellationToken.None);
            await subject.SaveAsync(second, secondReference, CancellationToken.None);
        }

        using var firstLoaded = await subject.LoadAsync(
            directoryUri,
            firstReference,
            CancellationToken.None);
        using var secondLoaded = await subject.LoadAsync(
            directoryUri,
            secondReference,
            CancellationToken.None);
        AssertAccount(
            firstLoaded,
            directoryUri,
            firstAccountUri,
            firstKey);
        AssertAccount(
            secondLoaded,
            directoryUri,
            secondAccountUri,
            secondKey);
    }

    [TestMethod]
    public async Task LoadRepairsDatabaseAfterVaultFirstCrashWindow()
    {
        var originalStore = CreateStore();
        using var vault = new MemorySecretVault();
        var reference = new SecretReference(
            Guid.Parse("9c9271c8-9595-412a-97c6-148f32034f7a"));
        var directoryUri = new Uri("https://acme.example.test/directory");
        var accountUri = new Uri("https://acme.example.test/account/301");
        var accountKey = CreateSyntheticKey("vault-first-crash-key");
        var originalSubject = CreateSubject(originalStore, vault);

        using (var account = new AcmeAccount(directoryUri, accountUri, accountKey))
        {
            await originalSubject.SaveAsync(
                account,
                reference,
                CancellationToken.None);
        }

        var recoveryStore = CreateStore();
        Assert.IsNull(
            recoveryStore.FindAcmeAccount(directoryUri, reference.ToString()));
        var recoverySubject = CreateSubject(recoveryStore, vault);

        using var recovered = await recoverySubject.LoadAsync(
            directoryUri,
            reference,
            CancellationToken.None);
        AssertAccount(recovered, directoryUri, accountUri, accountKey);
        var repairedRecord = recoveryStore.FindAcmeAccount(
            directoryUri,
            reference.ToString());
        Assert.IsNotNull(repairedRecord);
        Assert.AreEqual(reference.Value, repairedRecord.Id.Value);
        Assert.AreEqual(accountUri, repairedRecord.AccountUri);
        Assert.AreEqual(AcmeAccountStatus.Valid, repairedRecord.Status);
    }

    [TestMethod]
    public async Task LoadFailsClosedForMismatchedDirectoryOrSecretReference()
    {
        var store = CreateStore();
        using var vault = new MemorySecretVault();
        var subject = CreateSubject(store, vault);
        var reference = new SecretReference(
            Guid.Parse("5a34ff13-e70e-44d1-9813-e29106f4bc80"));
        var otherReference = new SecretReference(
            Guid.Parse("9f0844e8-2cdd-4441-af25-64005c9e6211"));
        var directoryUri = new Uri("https://acme.example.test/directory");
        var otherDirectoryUri = new Uri("https://other-acme.example.test/directory");
        var accountUri = new Uri("https://acme.example.test/account/401");
        var accountKey = CreateSyntheticKey("directory-binding-key");

        using (var account = new AcmeAccount(directoryUri, accountUri, accountKey))
        {
            await subject.SaveAsync(account, reference, CancellationToken.None);
        }

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => subject.LoadAsync(
                otherDirectoryUri,
                reference,
                CancellationToken.None));
        Assert.IsNull(
            await subject.LoadAsync(
                directoryUri,
                otherReference,
                CancellationToken.None));
    }

    [TestMethod]
    public async Task CorruptVersionedEnvelopeFailsClosed()
    {
        var store = CreateStore();
        using var vault = new MemorySecretVault();
        var subject = CreateSubject(store, vault);
        var reference = new SecretReference(
            Guid.Parse("3bf4860e-c432-475a-85a5-85d976091d1a"));
        var corruptEnvelope = "CBACME1\0"u8.ToArray();
        vault.Store(reference, corruptEnvelope);

        await Assert.ThrowsExactlyAsync<InvalidDataException>(
            () => subject.LoadAsync(
                new Uri("https://acme.example.test/directory"),
                reference,
                CancellationToken.None));
    }

    [TestMethod]
    public async Task LegacyRawKeyLoadsAndMigratesToEnvelopeOnSave()
    {
        var store = CreateStore();
        using var vault = new MemorySecretVault();
        var subject = CreateSubject(store, vault);
        var reference = new SecretReference(
            Guid.Parse("982e10ea-93d6-4efb-b279-a25ead5317dc"));
        var directoryUri = new Uri("https://acme.example.test/directory");
        var accountUri = new Uri("https://acme.example.test/account/501");
        var legacyKey = CreateSyntheticKey("legacy-raw-account-key");
        vault.Store(reference, legacyKey);
        _ = store.CreateOrGetAcmeAccount(
            new AcmeAccountRecord(
                new AcmeAccountId(reference.Value),
                directoryUri,
                accountUri,
                contactEmail: null,
                reference.ToString(),
                AcmeAccountStatus.Valid,
                testTime,
                testTime));

        using var loaded = await subject.LoadAsync(
            directoryUri,
            reference,
            CancellationToken.None);
        Assert.IsNotNull(loaded);
        AssertAccount(loaded, directoryUri, accountUri, legacyKey);

        await subject.SaveAsync(loaded, reference, CancellationToken.None);
        var migrated = vault.CopyStored(reference);
        try
        {
            Assert.IsFalse(migrated.AsSpan().SequenceEqual(legacyKey));
            Assert.IsTrue(
                migrated.AsSpan().StartsWith("CBACME1\0"u8),
                "Saving a legacy raw key must replace it with a versioned envelope.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(migrated);
        }

        using var reloaded = await subject.LoadAsync(
            directoryUri,
            reference,
            CancellationToken.None);
        AssertAccount(reloaded, directoryUri, accountUri, legacyKey);
    }

    private SqliteProductionStore CreateStore()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "CertBaton.UnitTests",
            Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(directory);
        testDirectories.Add(directory);
        var store = new SqliteProductionStore(Path.Combine(directory, "state.db"));
        store.Initialize(testTime);
        return store;
    }

    private static VaultBackedAcmeAccountStore CreateSubject(
        SqliteProductionStore store,
        ISecretVault vault) =>
        new(store, vault, new FixedTimeProvider(testTime));

    private static byte[] CreateSyntheticKey(string marker) =>
        Encoding.UTF8.GetBytes(
            $"-----BEGIN PRIVATE KEY-----\n{marker}\n-----END PRIVATE KEY-----\n");

    private static void AssertAccount(
        AcmeAccount? account,
        Uri expectedDirectoryUri,
        Uri expectedAccountUri,
        ReadOnlySpan<byte> expectedKey)
    {
        Assert.IsNotNull(account);
        Assert.AreEqual(expectedDirectoryUri, account.DirectoryUri);
        Assert.AreEqual(expectedAccountUri, account.AccountUri);
        var actualKey = account.ExportAccountKeyPem();
        try
        {
            Assert.IsTrue(
                actualKey.AsSpan().SequenceEqual(expectedKey),
                "The loaded account key did not match its exact secret reference.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualKey);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class MemorySecretVault : ISecretVault, IDisposable
    {
        private readonly Dictionary<Guid, byte[]> records = [];

        public bool Contains(SecretReference reference) =>
            records.ContainsKey(reference.Value);

        public void Store(
            SecretReference reference,
            ReadOnlySpan<byte> secret,
            bool replace = false)
        {
            if (records.TryGetValue(reference.Value, out var existing))
            {
                if (!replace)
                {
                    throw new IOException("The secret already exists.");
                }

                CryptographicOperations.ZeroMemory(existing);
            }

            records[reference.Value] = secret.ToArray();
        }

        public void ImportProtected(
            SecretReference reference,
            ReadOnlySpan<byte> protectedSecret,
            bool replace = false) =>
            Store(reference, protectedSecret, replace);

        public byte[] Read(SecretReference reference) =>
            records.TryGetValue(reference.Value, out var secret)
                ? secret.ToArray()
                : throw new KeyNotFoundException("The secret does not exist.");

        public byte[] CopyStored(SecretReference reference) => Read(reference);

        public bool Delete(SecretReference reference)
        {
            if (!records.Remove(reference.Value, out var secret))
            {
                return false;
            }

            CryptographicOperations.ZeroMemory(secret);
            return true;
        }

        public void Dispose()
        {
            foreach (var secret in records.Values)
            {
                CryptographicOperations.ZeroMemory(secret);
            }

            records.Clear();
        }
    }
}
