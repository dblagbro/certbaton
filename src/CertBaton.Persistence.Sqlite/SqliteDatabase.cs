using System.Globalization;
using Microsoft.Data.Sqlite;

namespace CertBaton.Persistence.Sqlite;

internal sealed class SqliteDatabase
{
    private static readonly Version minimumSqliteVersion = new(3, 51, 3);
    private static readonly object nativeInitializationGate = new();
    private static bool nativeProviderInitialized;
    private readonly object initializationGate = new();
    private bool initialized;
    private Version? runtimeSqliteVersion;

    public SqliteDatabase(string databasePath)
    {
        DatabasePath = ValidateLocalAbsolutePath(databasePath);
    }

    public string DatabasePath { get; }

    public Version RuntimeSqliteVersion =>
        runtimeSqliteVersion
        ?? throw new InvalidOperationException(
            "The database must be initialized before its SQLite runtime version is available.");

    public void Initialize(DateTimeOffset initializedAtUtc)
    {
        lock (initializationGate)
        {
            if (initialized)
            {
                return;
            }

            InitializeNativeProvider();
            Directory.CreateDirectory(
                Path.GetDirectoryName(DatabasePath)
                ?? throw new InvalidOperationException(
                    "The database path does not have a parent directory."));

            using var connection = OpenConnection();
            runtimeSqliteVersion = ReadAndValidateRuntimeVersion(connection);
            SqliteSchema.EnsureCurrent(connection, initializedAtUtc);
            initialized = true;
        }
    }

    public SqliteConnection OpenConnection()
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = SqliteSchema.BusyTimeoutMilliseconds / 1_000,
        }.ToString();
        var connection = new SqliteConnection(connectionString);
        connection.Open();

        try
        {
            SetAndVerifyPragmas(connection);
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static void InitializeNativeProvider()
    {
        lock (nativeInitializationGate)
        {
            if (nativeProviderInitialized)
            {
                return;
            }

            SQLitePCL.Batteries_V2.Init();
            nativeProviderInitialized = true;
        }
    }

    private static void SetAndVerifyPragmas(SqliteConnection connection)
    {
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA journal_mode = DELETE;";
            var journalMode = Convert.ToString(
                command.ExecuteScalar(),
                CultureInfo.InvariantCulture);
            if (!string.Equals(journalMode, "delete", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "SQLite did not accept DELETE journal mode.");
            }
        }

        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                $"""
                PRAGMA synchronous = EXTRA;
                PRAGMA foreign_keys = ON;
                PRAGMA trusted_schema = OFF;
                PRAGMA busy_timeout = {SqliteSchema.BusyTimeoutMilliseconds};
                """;
            _ = command.ExecuteNonQuery();
        }

        VerifyPragmaInteger(connection, "PRAGMA synchronous;", 3);
        VerifyPragmaInteger(connection, "PRAGMA foreign_keys;", 1);
        VerifyPragmaInteger(connection, "PRAGMA trusted_schema;", 0);
        VerifyPragmaInteger(
            connection,
            "PRAGMA busy_timeout;",
            SqliteSchema.BusyTimeoutMilliseconds);
    }

    private static void VerifyPragmaInteger(
        SqliteConnection connection,
        string commandText,
        long expected)
    {
        using var command = connection.CreateCommand();
        command.CommandText = commandText;
        var actual = Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"SQLite setting verification failed for {commandText}");
        }
    }

    private static Version ReadAndValidateRuntimeVersion(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT sqlite_version();";
        var versionText = Convert.ToString(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
        if (!Version.TryParse(versionText, out var version))
        {
            throw new InvalidOperationException(
                "The SQLite runtime returned an invalid version.");
        }

        if (version < minimumSqliteVersion)
        {
            throw new NotSupportedException(
                $"SQLite {minimumSqliteVersion} or newer is required.");
        }

        return version;
    }

    private static string ValidateLocalAbsolutePath(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        if (!Path.IsPathFullyQualified(databasePath))
        {
            throw new ArgumentException(
                "The SQLite database path must be absolute.",
                nameof(databasePath));
        }

        var fullPath = Path.GetFullPath(databasePath);
        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The SQLite database path must use local storage.",
                nameof(databasePath));
        }

        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException(
                "The SQLite database path must have a local volume root.",
                nameof(databasePath));
        }

        var drive = new DriveInfo(root);
        if (drive.DriveType == DriveType.Network ||
            !string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The SQLite database path must be on a local NTFS volume.",
                nameof(databasePath));
        }

        return fullPath;
    }
}
