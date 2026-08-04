using System.Globalization;
using Microsoft.Data.Sqlite;

namespace CertBaton.Persistence.Sqlite;

public static class OfflineProductionStateInspector
{
    public static OfflineProductionStateSnapshot Inspect(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        if (!Path.IsPathFullyQualified(databasePath))
        {
            throw new ArgumentException(
                "The offline database path must be absolute.",
                nameof(databasePath));
        }

        var fullPath = Path.GetFullPath(databasePath);
        if (!File.Exists(fullPath))
        {
            return new OfflineProductionStateSnapshot(
                DatabaseExists: false,
                ApplicationId: 0,
                SchemaVersion: 0,
                IntegrityCheck: "not-created",
                ActiveLiveOperationCount: 0);
        }

        if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                "The offline database cannot be a reparse point.");
        }

        SQLitePCL.Batteries_V2.Init();
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = SqliteSchema.BusyTimeoutMilliseconds / 1_000,
        }.ToString();
        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        var applicationId = ReadInt64(connection, "PRAGMA application_id;");
        var schemaVersion = ReadInt64(connection, "PRAGMA user_version;");
        var integrity = ReadString(connection, "PRAGMA integrity_check;");
        var activeOperationCount = HasOperationsTable(connection)
            ? ReadInt64(
                connection,
                """
                SELECT COUNT(*)
                FROM operations
                WHERE status IN (
                    'Queued', 'Running', 'Blocked', 'RollbackRequired');
                """)
            : 0;

        return new OfflineProductionStateSnapshot(
            DatabaseExists: true,
            ApplicationId: checked((int)applicationId),
            SchemaVersion: checked((int)schemaVersion),
            IntegrityCheck: integrity,
            ActiveLiveOperationCount: activeOperationCount);
    }

    private static bool HasOperationsTable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT COUNT(*)
            FROM sqlite_schema
            WHERE type = 'table' AND name = 'operations';
            """;
        return Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture) == 1;
    }

    private static long ReadInt64(
        SqliteConnection connection,
        string commandText)
    {
        using var command = connection.CreateCommand();
        command.CommandText = commandText;
        return Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
    }

    private static string ReadString(
        SqliteConnection connection,
        string commandText)
    {
        using var command = connection.CreateCommand();
        command.CommandText = commandText;
        return Convert.ToString(
                   command.ExecuteScalar(),
                   CultureInfo.InvariantCulture)
               ?? throw new InvalidDataException(
                   "SQLite did not return an integrity-check result.");
    }
}

public sealed record OfflineProductionStateSnapshot(
    bool DatabaseExists,
    int ApplicationId,
    int SchemaVersion,
    string IntegrityCheck,
    long ActiveLiveOperationCount);
