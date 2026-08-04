using CertBaton.Persistence.Sqlite;
using CertBaton.Service;
using Microsoft.Data.Sqlite;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class InstallerMaintenanceSafetyTests
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
    public void OfflineInspectionDoesNotCreateMissingDatabase()
    {
        var databasePath = Path.Combine(CreateTestDirectory(), "missing.db");

        var snapshot = OfflineProductionStateInspector.Inspect(databasePath);

        Assert.IsFalse(snapshot.DatabaseExists);
        Assert.AreEqual(0, snapshot.ApplicationId);
        Assert.AreEqual(0, snapshot.SchemaVersion);
        Assert.AreEqual("not-created", snapshot.IntegrityCheck);
        Assert.AreEqual(0, snapshot.ActiveLiveOperationCount);
        Assert.IsFalse(File.Exists(databasePath));
    }

    [TestMethod]
    public void OfflineInspectionReadsInitializedDatabaseWithoutMigratingIt()
    {
        var databasePath = Path.Combine(CreateTestDirectory(), "certbaton.db");
        var store = new SqliteProductionStore(databasePath);
        store.Initialize(new DateTimeOffset(2026, 7, 31, 18, 0, 0, TimeSpan.Zero));
        var before = File.GetLastWriteTimeUtc(databasePath);

        var snapshot = OfflineProductionStateInspector.Inspect(databasePath);

        Assert.IsTrue(snapshot.DatabaseExists);
        Assert.AreEqual(
            SqliteProductionStore.ApplicationId,
            snapshot.ApplicationId);
        Assert.AreEqual(
            SqliteProductionStore.CurrentSchemaVersion,
            snapshot.SchemaVersion);
        Assert.AreEqual("ok", snapshot.IntegrityCheck);
        Assert.AreEqual(0, snapshot.ActiveLiveOperationCount);
        Assert.AreEqual(before, File.GetLastWriteTimeUtc(databasePath));
    }

    [TestMethod]
    public void OfflineInspectionFindsQueuedLiveOperation()
    {
        var databasePath = Path.Combine(CreateTestDirectory(), "certbaton.db");
        var store = new SqliteProductionStore(databasePath);
        store.Initialize(new DateTimeOffset(2026, 7, 31, 18, 0, 0, TimeSpan.Zero));
        using (var connection = new SqliteConnection(
                   $"Data Source={databasePath};Mode=ReadWrite;Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText =
                """
                PRAGMA foreign_keys = OFF;

                INSERT INTO operations (
                    operation_id,
                    target_id,
                    request_key,
                    kind,
                    status,
                    requested_at_ms,
                    updated_at_ms,
                    started_at_ms,
                    completed_at_ms,
                    execution_epoch,
                    failure_code
                )
                VALUES (
                    $operation_id,
                    $target_id,
                    'installer-active-operation-test',
                    'Renewal',
                    'Queued',
                    1,
                    1,
                    NULL,
                    NULL,
                    NULL,
                    NULL
                );
                """;
            command.Parameters.AddWithValue(
                "$operation_id",
                Guid.CreateVersion7().ToString("D"));
            command.Parameters.AddWithValue(
                "$target_id",
                Guid.CreateVersion7().ToString("D"));
            _ = command.ExecuteNonQuery();
        }

        var snapshot = OfflineProductionStateInspector.Inspect(databasePath);

        Assert.AreEqual(1, snapshot.ActiveLiveOperationCount);
    }

    [TestMethod]
    public async Task MaintenanceGateRejectsManualWorkAndOpensAfterMarkerRemoval()
    {
        var markerPath = Path.Combine(
            CreateTestDirectory(),
            ServiceStatePath.MaintenanceMarkerFileName);
        await File.WriteAllTextAsync(markerPath, "maintenance");
        var gate = new LiveMaintenanceGate(markerPath);

        Assert.IsTrue(gate.IsPaused);
        Assert.ThrowsExactly<InvalidOperationException>(gate.ThrowIfPaused);
        var waitTask = gate.WaitUntilOpenAsync(CancellationToken.None);
        Assert.IsFalse(waitTask.IsCompleted);

        File.Delete(markerPath);
        await waitTask.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.IsFalse(gate.IsPaused);
        gate.ThrowIfPaused();
    }

    private string CreateTestDirectory()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            $"CertBaton.InstallerMaintenance-{Guid.CreateVersion7():N}");
        Directory.CreateDirectory(directory);
        testDirectories.Add(directory);
        return directory;
    }
}
