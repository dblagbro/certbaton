using System.Collections.ObjectModel;
using System.Globalization;
using CertBaton.Application.Simulation.Persistence;
using CertBaton.Domain.Renewals;
using Microsoft.Data.Sqlite;

namespace CertBaton.Persistence.Sqlite;

/// <summary>
/// Stores simulator jobs using short, synchronous SQLite transactions.
/// Microsoft.Data.Sqlite performs synchronous I/O even through its asynchronous APIs,
/// so callers must serialize mutations on a non-UI service worker.
/// </summary>
public sealed class SqliteSimulationJobStore : ISimulationJobStore
{
    public const int ApplicationId = SqliteSchema.ApplicationId;
    public const int CurrentSchemaVersion = SqliteSchema.CurrentVersion;
    public const int BusyTimeoutMilliseconds = SqliteSchema.BusyTimeoutMilliseconds;

    private const string RecoveryCode = "persistence.recovered_interrupted";
    private const string RecoveryDescription =
        "The service recovered a job whose prior execution ended without a terminal result.";
    private const int MaximumRequestKeyLength = 200;
    private const int MaximumCodeLength = 128;
    private const int MaximumDescriptionLength = 1_024;
    private const string JobProjectionColumns =
        """
        job_id,
        request_key,
        failure_stage_index,
        status,
        created_at_ms,
        updated_at_ms,
        execution_epoch,
        claimed_at_ms,
        completed_at_ms
        """;
    private const string JobProjectionSql =
        "SELECT " + JobProjectionColumns + " FROM jobs";
    private readonly object initializationGate = new();
    private readonly SqliteDatabase database;
    private bool initialized;

    public SqliteSimulationJobStore(string databasePath)
    {
        database = new SqliteDatabase(databasePath);
    }

    public string DatabasePath => database.DatabasePath;

    public Version RuntimeSqliteVersion => database.RuntimeSqliteVersion;

    public void Initialize(DateTimeOffset recoveredAtUtc)
    {
        lock (initializationGate)
        {
            if (initialized)
            {
                return;
            }

            database.Initialize(recoveredAtUtc);
            using var connection = database.OpenConnection();
            RecoverRunningJobs(connection, recoveredAtUtc);
            initialized = true;
        }
    }

    public SimulationJobSnapshot CreateOrGetJob(
        Guid jobId,
        string requestKey,
        RenewalStage? failureStage,
        DateTimeOffset createdAtUtc)
    {
        EnsureInitialized();
        ValidateGuid(jobId, nameof(jobId));
        ValidateRequestKey(requestKey);
        ValidateOptionalStage(failureStage, nameof(failureStage));
        var createdAtMilliseconds = ToUnixMilliseconds(createdAtUtc);

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindJobByRequestKey(connection, transaction, requestKey);
        if (existing is not null)
        {
            if (existing.FailureStage != failureStage)
            {
                throw new SimulationIdempotencyConflictException();
            }

            transaction.Commit();
            return existing;
        }

        EnsureNoActiveJob(connection, transaction);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO jobs (
                    job_id,
                    request_key,
                    failure_stage_index,
                    status,
                    created_at_ms,
                    updated_at_ms
                )
                VALUES (
                    $job_id,
                    $request_key,
                    $failure_stage_index,
                    'Queued',
                    $created_at_ms,
                    $created_at_ms
                )
                ON CONFLICT(request_key) DO NOTHING;
                """;
            command.Parameters.AddWithValue("$job_id", ToDatabaseGuid(jobId));
            command.Parameters.AddWithValue("$request_key", requestKey);
            command.Parameters.AddWithValue(
                "$failure_stage_index",
                failureStage.HasValue ? (int)failureStage.Value : DBNull.Value);
            command.Parameters.AddWithValue("$created_at_ms", createdAtMilliseconds);
            _ = command.ExecuteNonQuery();
        }

        var result = FindJobByRequestKey(connection, transaction, requestKey)
            ?? throw new InvalidOperationException(
                "The job could not be read after its idempotent creation.");
        transaction.Commit();
        return result;
    }

    public SimulationJobSnapshot? TryClaimNextQueuedJob(
        Guid executionEpoch,
        DateTimeOffset claimedAtUtc)
    {
        EnsureInitialized();
        ValidateGuid(executionEpoch, nameof(executionEpoch));
        var claimedAtMilliseconds = ToUnixMilliseconds(claimedAtUtc);

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"""
            UPDATE jobs
            SET status = 'Running',
                execution_epoch = $execution_epoch,
                claimed_at_ms = $claimed_at_ms,
                updated_at_ms = $claimed_at_ms
            WHERE job_id = (
                SELECT job_id
                FROM jobs
                WHERE status = 'Queued'
                ORDER BY job_sequence
                LIMIT 1
            )
            AND status = 'Queued'
            RETURNING {JobProjectionColumns};
            """;
        command.Parameters.AddWithValue(
            "$execution_epoch",
            ToDatabaseGuid(executionEpoch));
        command.Parameters.AddWithValue("$claimed_at_ms", claimedAtMilliseconds);

        SimulationJobSnapshot? result;
        using (var reader = command.ExecuteReader())
        {
            result = reader.Read() ? ReadJob(reader) : null;
        }

        transaction.Commit();
        return result;
    }

    public void AppendStageEvidence(
        Guid jobId,
        Guid executionEpoch,
        RenewalStage stage,
        RenewalStageOutcome outcome,
        DateTimeOffset recordedAtUtc,
        string code,
        string description)
    {
        EnsureInitialized();
        ValidateGuid(jobId, nameof(jobId));
        ValidateGuid(executionEpoch, nameof(executionEpoch));
        ValidateStage(stage, nameof(stage));
        ValidateOutcome(outcome, nameof(outcome));
        ValidateEvidenceText(code, description);
        var recordedAtMilliseconds = ToUnixMilliseconds(recordedAtUtc);

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        EnsureJobIsOwnedByExecutionEpoch(
            connection,
            transaction,
            jobId,
            executionEpoch);
        var existingStages = ReadStageRows(connection, transaction, jobId);
        EnsureStageCanBeAppended(existingStages, stage);
        InsertEvidence(
            connection,
            transaction,
            jobId,
            SimulationEvidenceKind.Stage,
            stage,
            outcome,
            recordedAtMilliseconds,
            code,
            description);
        UpdateJobTimestamp(
            connection,
            transaction,
            jobId,
            recordedAtMilliseconds);
        transaction.Commit();
    }

    public void CompleteJob(
        Guid jobId,
        Guid executionEpoch,
        SimulationJobStatus terminalStatus,
        DateTimeOffset completedAtUtc,
        string code,
        string description)
    {
        EnsureInitialized();
        ValidateGuid(jobId, nameof(jobId));
        ValidateGuid(executionEpoch, nameof(executionEpoch));
        ValidateTerminalStatus(terminalStatus);
        ValidateEvidenceText(code, description);
        var completedAtMilliseconds = ToUnixMilliseconds(completedAtUtc);

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        EnsureJobIsOwnedByExecutionEpoch(
            connection,
            transaction,
            jobId,
            executionEpoch);
        var stageRows = ReadStageRows(connection, transaction, jobId);
        EnsureTerminalOutcomeIsProven(stageRows, terminalStatus);
        InsertEvidence(
            connection,
            transaction,
            jobId,
            SimulationEvidenceKind.Terminal,
            null,
            null,
            completedAtMilliseconds,
            code,
            description);

        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            UPDATE jobs
            SET status = $status,
                updated_at_ms = $completed_at_ms,
                completed_at_ms = $completed_at_ms
            WHERE job_id = $job_id
              AND status = 'Running';
            """;
        command.Parameters.AddWithValue("$status", terminalStatus.ToString());
        command.Parameters.AddWithValue("$completed_at_ms", completedAtMilliseconds);
        command.Parameters.AddWithValue("$job_id", ToDatabaseGuid(jobId));
        if (command.ExecuteNonQuery() != 1)
        {
            throw new InvalidOperationException(
                "The running job could not be completed.");
        }

        transaction.Commit();
    }

    public SimulationJobSnapshot? FindJob(Guid jobId)
    {
        EnsureInitialized();
        ValidateGuid(jobId, nameof(jobId));
        using var connection = database.OpenConnection();
        return FindJob(connection, null, jobId);
    }

    public SimulationJobDetails? FindJobWithEvidence(Guid jobId)
    {
        EnsureInitialized();
        ValidateGuid(jobId, nameof(jobId));
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction();
        var job = FindJob(connection, transaction, jobId);
        if (job is null)
        {
            transaction.Commit();
            return null;
        }

        var evidence = ReadEvidence(connection, transaction, jobId);
        transaction.Commit();
        return new SimulationJobDetails(job, evidence);
    }

    public SimulationJobDetails? GetLatestJobWithEvidence()
    {
        EnsureInitialized();
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction();
        SimulationJobSnapshot? job;
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                $"""
                {JobProjectionSql}
                ORDER BY job_sequence DESC
                LIMIT 1;
                """;
            using var reader = command.ExecuteReader();
            job = reader.Read() ? ReadJob(reader) : null;
        }

        if (job is null)
        {
            transaction.Commit();
            return null;
        }

        var evidence = ReadEvidence(connection, transaction, job.JobId);
        transaction.Commit();
        return new SimulationJobDetails(job, evidence);
    }

    public IReadOnlyList<SimulationJobEvidence> ReadEvidence(Guid jobId)
    {
        EnsureInitialized();
        ValidateGuid(jobId, nameof(jobId));
        using var connection = database.OpenConnection();
        return ReadEvidence(connection, null, jobId);
    }

    private static void RecoverRunningJobs(
        SqliteConnection connection,
        DateTimeOffset recoveredAtUtc)
    {
        var recoveredAtMilliseconds = ToUnixMilliseconds(recoveredAtUtc);
        using var transaction = connection.BeginTransaction(deferred: false);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO evidence (
                    job_id,
                    sequence,
                    kind,
                    stage_index,
                    stage_outcome,
                    recorded_at_ms,
                    code,
                    description
                )
                SELECT jobs.job_id,
                       COALESCE((
                           SELECT MAX(existing.sequence)
                           FROM evidence AS existing
                           WHERE existing.job_id = jobs.job_id
                       ), 0) + 1,
                       'Recovery',
                       NULL,
                       NULL,
                       $recovered_at_ms,
                       $code,
                       $description
                FROM jobs
                WHERE jobs.status = 'Running';
                """;
            command.Parameters.AddWithValue(
                "$recovered_at_ms",
                recoveredAtMilliseconds);
            command.Parameters.AddWithValue("$code", RecoveryCode);
            command.Parameters.AddWithValue("$description", RecoveryDescription);
            _ = command.ExecuteNonQuery();
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE jobs
                SET status = 'Interrupted',
                    updated_at_ms = $recovered_at_ms,
                    completed_at_ms = $recovered_at_ms
                WHERE status = 'Running';
                """;
            command.Parameters.AddWithValue(
                "$recovered_at_ms",
                recoveredAtMilliseconds);
            _ = command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    private static SimulationJobSnapshot? FindJobByRequestKey(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string requestKey)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"""
            {JobProjectionSql}
            WHERE request_key = $request_key;
            """;
        command.Parameters.AddWithValue("$request_key", requestKey);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadJob(reader) : null;
    }

    private static void EnsureNoActiveJob(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT EXISTS (
                SELECT 1
                FROM jobs
                WHERE status IN ('Queued', 'Running')
            );
            """;
        var activeJobExists = Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture) != 0;
        if (activeJobExists)
        {
            throw new SimulationJobAlreadyActiveException();
        }
    }

    private static SimulationJobSnapshot? FindJob(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        Guid jobId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"""
            {JobProjectionSql}
            WHERE job_id = $job_id;
            """;
        command.Parameters.AddWithValue("$job_id", ToDatabaseGuid(jobId));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadJob(reader) : null;
    }

    private static SimulationJobSnapshot ReadJob(SqliteDataReader reader)
    {
        var jobId = ReadDatabaseGuid(reader.GetString(0));
        var requestKey = reader.GetString(1);
        RenewalStage? failureStage = reader.IsDBNull(2)
            ? null
            : ReadStage(reader.GetInt32(2));
        var status = ParseEnum<SimulationJobStatus>(reader.GetString(3), "job status");
        var createdAtUtc = FromUnixMilliseconds(reader.GetInt64(4));
        var updatedAtUtc = FromUnixMilliseconds(reader.GetInt64(5));
        Guid? executionEpoch = reader.IsDBNull(6)
            ? null
            : ReadDatabaseGuid(reader.GetString(6));
        DateTimeOffset? claimedAtUtc = reader.IsDBNull(7)
            ? null
            : FromUnixMilliseconds(reader.GetInt64(7));
        DateTimeOffset? completedAtUtc = reader.IsDBNull(8)
            ? null
            : FromUnixMilliseconds(reader.GetInt64(8));

        return new SimulationJobSnapshot(
            jobId,
            requestKey,
            failureStage,
            status,
            createdAtUtc,
            updatedAtUtc,
            executionEpoch,
            claimedAtUtc,
            completedAtUtc);
    }

    private static ReadOnlyCollection<SimulationJobEvidence> ReadEvidence(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        Guid jobId)
    {
        var result = new List<SimulationJobEvidence>();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT job_id,
                   sequence,
                   kind,
                   stage_index,
                   stage_outcome,
                   recorded_at_ms,
                   code,
                   description
            FROM evidence
            WHERE job_id = $job_id
            ORDER BY sequence;
            """;
        command.Parameters.AddWithValue("$job_id", ToDatabaseGuid(jobId));
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var kind = ParseEnum<SimulationEvidenceKind>(
                reader.GetString(2),
                "evidence kind");
            RenewalStage? stage = reader.IsDBNull(3)
                ? null
                : ReadStage(reader.GetInt32(3));
            RenewalStageOutcome? outcome = reader.IsDBNull(4)
                ? null
                : ParseEnum<RenewalStageOutcome>(
                    reader.GetString(4),
                    "stage outcome");
            result.Add(
                new SimulationJobEvidence(
                    ReadDatabaseGuid(reader.GetString(0)),
                    reader.GetInt64(1),
                    kind,
                    stage,
                    outcome,
                    FromUnixMilliseconds(reader.GetInt64(5)),
                    reader.GetString(6),
                    reader.GetString(7)));
        }

        return result.AsReadOnly();
    }

    private static List<(RenewalStage Stage, RenewalStageOutcome Outcome)> ReadStageRows(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid jobId)
    {
        var result = new List<(RenewalStage Stage, RenewalStageOutcome Outcome)>();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT stage_index, stage_outcome
            FROM evidence
            WHERE job_id = $job_id
              AND kind = 'Stage'
            ORDER BY sequence;
            """;
        command.Parameters.AddWithValue("$job_id", ToDatabaseGuid(jobId));
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(
                (
                    ReadStage(reader.GetInt32(0)),
                    ParseEnum<RenewalStageOutcome>(
                        reader.GetString(1),
                        "stage outcome")
                ));
        }

        return result;
    }

    private static void EnsureJobIsOwnedByExecutionEpoch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid jobId,
        Guid executionEpoch)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT EXISTS (
                SELECT 1
                FROM jobs
                WHERE job_id = $job_id
                  AND status = 'Running'
                  AND execution_epoch = $execution_epoch
            );
            """;
        command.Parameters.AddWithValue("$job_id", ToDatabaseGuid(jobId));
        command.Parameters.AddWithValue(
            "$execution_epoch",
            ToDatabaseGuid(executionEpoch));
        var isOwnedRunningJob = Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture) != 0;
        if (!isOwnedRunningJob)
        {
            throw new InvalidOperationException(
                "The simulation job is not running under the supplied execution epoch.");
        }
    }

    private static void EnsureStageCanBeAppended(
        List<(RenewalStage Stage, RenewalStageOutcome Outcome)> existingStages,
        RenewalStage stage)
    {
        if (existingStages.Count >= RenewalPipeline.Stages.Count)
        {
            throw new InvalidOperationException(
                "All renewal stages already have evidence.");
        }

        for (var index = 0; index < existingStages.Count; index++)
        {
            if (existingStages[index].Stage != RenewalPipeline.Stages[index] ||
                existingStages[index].Outcome != RenewalStageOutcome.Succeeded)
            {
                throw new InvalidOperationException(
                    "Existing stage evidence does not prove an ordered successful prefix.");
            }
        }

        if (stage != RenewalPipeline.Stages[existingStages.Count])
        {
            throw new InvalidOperationException(
                "Stage evidence must be appended in renewal-pipeline order.");
        }
    }

    private static void EnsureTerminalOutcomeIsProven(
        List<(RenewalStage Stage, RenewalStageOutcome Outcome)> stageRows,
        SimulationJobStatus terminalStatus)
    {
        if (terminalStatus == SimulationJobStatus.Succeeded)
        {
            if (stageRows.Count != RenewalPipeline.Stages.Count)
            {
                throw new InvalidOperationException(
                    "Success requires evidence for every renewal stage.");
            }

            for (var index = 0; index < stageRows.Count; index++)
            {
                if (stageRows[index].Stage != RenewalPipeline.Stages[index] ||
                    stageRows[index].Outcome != RenewalStageOutcome.Succeeded)
                {
                    throw new InvalidOperationException(
                        "Success requires ordered successful evidence through verification and cleanup.");
                }
            }

            return;
        }

        if (stageRows.Count == 0)
        {
            throw new InvalidOperationException(
                "A failed or cancelled job requires terminal stage evidence.");
        }

        for (var index = 0; index < stageRows.Count - 1; index++)
        {
            if (stageRows[index].Stage != RenewalPipeline.Stages[index] ||
                stageRows[index].Outcome != RenewalStageOutcome.Succeeded)
            {
                throw new InvalidOperationException(
                    "Terminal evidence does not follow an ordered successful prefix.");
            }
        }

        var lastIndex = stageRows.Count - 1;
        if (stageRows[lastIndex].Stage != RenewalPipeline.Stages[lastIndex])
        {
            throw new InvalidOperationException(
                "Terminal stage evidence is out of order.");
        }

        var requiredOutcome = terminalStatus == SimulationJobStatus.Failed
            ? RenewalStageOutcome.Failed
            : RenewalStageOutcome.Cancelled;
        if (stageRows[lastIndex].Outcome != requiredOutcome)
        {
            throw new InvalidOperationException(
                "The requested terminal status is not proven by stage evidence.");
        }
    }

    private static void InsertEvidence(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid jobId,
        SimulationEvidenceKind kind,
        RenewalStage? stage,
        RenewalStageOutcome? outcome,
        long recordedAtMilliseconds,
        string code,
        string description)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO evidence (
                job_id,
                sequence,
                kind,
                stage_index,
                stage_outcome,
                recorded_at_ms,
                code,
                description
            )
            VALUES (
                $job_id,
                COALESCE((
                    SELECT MAX(existing.sequence)
                    FROM evidence AS existing
                    WHERE existing.job_id = $job_id
                ), 0) + 1,
                $kind,
                $stage_index,
                $stage_outcome,
                $recorded_at_ms,
                $code,
                $description
            );
            """;
        command.Parameters.AddWithValue("$job_id", ToDatabaseGuid(jobId));
        command.Parameters.AddWithValue("$kind", kind.ToString());
        command.Parameters.AddWithValue(
            "$stage_index",
            stage.HasValue ? (int)stage.Value : DBNull.Value);
        command.Parameters.AddWithValue(
            "$stage_outcome",
            outcome.HasValue ? outcome.Value.ToString() : DBNull.Value);
        command.Parameters.AddWithValue("$recorded_at_ms", recordedAtMilliseconds);
        command.Parameters.AddWithValue("$code", code);
        command.Parameters.AddWithValue("$description", description);
        _ = command.ExecuteNonQuery();
    }

    private static void UpdateJobTimestamp(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid jobId,
        long updatedAtMilliseconds)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            UPDATE jobs
            SET updated_at_ms = $updated_at_ms
            WHERE job_id = $job_id
              AND status = 'Running';
            """;
        command.Parameters.AddWithValue("$updated_at_ms", updatedAtMilliseconds);
        command.Parameters.AddWithValue("$job_id", ToDatabaseGuid(jobId));
        if (command.ExecuteNonQuery() != 1)
        {
            throw new InvalidOperationException(
                "The running job timestamp could not be updated.");
        }
    }

    private static void ValidateRequestKey(string requestKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestKey);
        if (requestKey.Length > MaximumRequestKeyLength ||
            !string.Equals(requestKey, requestKey.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The request key must be trimmed and no longer than 200 characters.",
                nameof(requestKey));
        }
    }

    private static void ValidateEvidenceText(string code, string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);
        if (code.Length > MaximumCodeLength ||
            !string.Equals(code, code.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The sanitized evidence code must be trimmed and no longer than 128 characters.",
                nameof(code));
        }

        if (description.Length > MaximumDescriptionLength ||
            !string.Equals(description, description.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The sanitized evidence description must be trimmed and no longer than 1024 characters.",
                nameof(description));
        }
    }

    private static void ValidateTerminalStatus(SimulationJobStatus status)
    {
        if (status is not SimulationJobStatus.Succeeded
            and not SimulationJobStatus.Failed
            and not SimulationJobStatus.Cancelled)
        {
            throw new ArgumentOutOfRangeException(
                nameof(status),
                status,
                "Only a proven success, failure, or cancellation can complete a running job.");
        }
    }

    private static void ValidateGuid(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "The identifier cannot be empty.",
                parameterName);
        }
    }

    private static void ValidateOptionalStage(
        RenewalStage? stage,
        string parameterName)
    {
        if (stage.HasValue)
        {
            ValidateStage(stage.Value, parameterName);
        }
    }

    private static void ValidateStage(RenewalStage stage, string parameterName)
    {
        if (!Enum.IsDefined(stage))
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                stage,
                "The renewal stage is invalid.");
        }
    }

    private static void ValidateOutcome(
        RenewalStageOutcome outcome,
        string parameterName)
    {
        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                outcome,
                "The renewal stage outcome is invalid.");
        }
    }

    private static RenewalStage ReadStage(int value)
    {
        var stage = (RenewalStage)value;
        ValidateStage(stage, nameof(value));
        return stage;
    }

    private static TEnum ParseEnum<TEnum>(string value, string fieldName)
        where TEnum : struct, Enum
    {
        if (!Enum.TryParse<TEnum>(value, ignoreCase: false, out var result) ||
            !Enum.IsDefined(result))
        {
            throw new InvalidOperationException(
                $"The persisted {fieldName} is invalid.");
        }

        return result;
    }

    private static string ToDatabaseGuid(Guid value) =>
        value.ToString("D", CultureInfo.InvariantCulture);

    private static Guid ReadDatabaseGuid(string value)
    {
        if (!Guid.TryParseExact(value, "D", out var result) ||
            !string.Equals(value, ToDatabaseGuid(result), StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "A persisted identifier is not in canonical GUID text form.");
        }

        return result;
    }

    private static long ToUnixMilliseconds(DateTimeOffset value) =>
        value.ToUniversalTime().ToUnixTimeMilliseconds();

    private static DateTimeOffset FromUnixMilliseconds(long value) =>
        DateTimeOffset.FromUnixTimeMilliseconds(value);

    private void EnsureInitialized()
    {
        if (!initialized)
        {
            throw new InvalidOperationException(
                "The SQLite simulation job store has not been initialized.");
        }
    }

}
