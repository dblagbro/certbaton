using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using CertBaton.Application.Persistence;
using CertBaton.Domain.Connections;
using CertBaton.Domain.Deployments;
using CertBaton.Domain.Operations;
using CertBaton.Domain.Scheduling;
using CertBaton.Domain.Targets;
using Microsoft.Data.Sqlite;

namespace CertBaton.Persistence.Sqlite;

/// <summary>
/// Stores production configuration and operation evidence through short,
/// synchronous transactions owned by the service persistence worker.
/// Secret values are prohibited; secret fields contain opaque vault references.
/// </summary>
public sealed class SqliteProductionStore : IProductionStore
{
    public const int ApplicationId = SqliteSchema.ApplicationId;
    public const int CurrentSchemaVersion = SqliteSchema.CurrentVersion;

    private const string ConnectionProjectionColumns =
        """
        connection_id,
        display_name,
        host,
        port,
        username,
        credential_reference,
        host_key_algorithm,
        host_key_fingerprint,
        raw_host_key,
        created_at_ms,
        updated_at_ms,
        enabled
        """;
    private const string DeploymentPlanProjectionColumns =
        """
        deployment_plan_id,
        target_id,
        kind,
        challenge_webroot,
        remote_incoming_root,
        certificate_path,
        private_key_path,
        created_at_ms,
        updated_at_ms,
        enabled
        """;
    private const string RenewalPolicyProjectionColumns =
        """
        renewal_policy_id,
        target_id,
        renew_before_days,
        check_interval_minutes,
        enabled,
        next_due_at_ms,
        created_at_ms,
        updated_at_ms
        """;
    private const string OperationProjectionColumns =
        """
        operation_id,
        target_id,
        request_key,
        status,
        requested_at_ms,
        updated_at_ms,
        started_at_ms,
        completed_at_ms,
        execution_epoch,
        failure_code
        """;
    private const string AuditEventProjectionColumns =
        """
        audit_event_id,
        event_sequence,
        operation_id,
        target_id,
        actor_sid,
        event_type,
        occurred_at_ms,
        code,
        description
        """;
    private readonly object initializationGate = new();
    private readonly SqliteDatabase database;
    private bool initialized;

    public SqliteProductionStore(string databasePath)
    {
        database = new SqliteDatabase(databasePath);
    }

    public string DatabasePath => database.DatabasePath;

    public Version RuntimeSqliteVersion => database.RuntimeSqliteVersion;

    public void Initialize(DateTimeOffset initializedAtUtc)
    {
        lock (initializationGate)
        {
            if (initialized)
            {
                return;
            }

            database.Initialize(initializedAtUtc);
            initialized = true;
        }
    }

    public void SaveConnection(ConnectionProfile connectionProfile)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(connectionProfile);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        SaveConnection(connection, transaction, connectionProfile);
        transaction.Commit();
    }

    private static void SaveConnection(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ConnectionProfile connectionProfile)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO connections (
                connection_id,
                display_name,
                host,
                port,
                username,
                credential_reference,
                host_key_algorithm,
                host_key_fingerprint,
                raw_host_key,
                created_at_ms,
                updated_at_ms,
                enabled
            )
            VALUES (
                $connection_id,
                $display_name,
                $host,
                $port,
                $username,
                $credential_reference,
                $host_key_algorithm,
                $host_key_fingerprint,
                $raw_host_key,
                $created_at_ms,
                $updated_at_ms,
                $enabled
            )
            ON CONFLICT(connection_id) DO UPDATE SET
                display_name = excluded.display_name,
                host = excluded.host,
                port = excluded.port,
                username = excluded.username,
                credential_reference = excluded.credential_reference,
                host_key_algorithm = excluded.host_key_algorithm,
                host_key_fingerprint = excluded.host_key_fingerprint,
                raw_host_key = excluded.raw_host_key,
                updated_at_ms = excluded.updated_at_ms,
                enabled = excluded.enabled;
            """;
        command.Parameters.AddWithValue(
            "$connection_id",
            ToDatabaseGuid(connectionProfile.Id.Value));
        command.Parameters.AddWithValue("$display_name", connectionProfile.DisplayName);
        command.Parameters.AddWithValue("$host", connectionProfile.Endpoint.Host);
        command.Parameters.AddWithValue("$port", connectionProfile.Endpoint.Port);
        command.Parameters.AddWithValue("$username", connectionProfile.Username);
        command.Parameters.AddWithValue(
            "$credential_reference",
            connectionProfile.CredentialReference);
        command.Parameters.AddWithValue(
            "$host_key_algorithm",
            connectionProfile.HostKeyAlgorithm ?? (object)DBNull.Value);
        command.Parameters.AddWithValue(
            "$host_key_fingerprint",
            connectionProfile.HostKeyFingerprint);
        command.Parameters.AddWithValue(
            "$raw_host_key",
            connectionProfile.ExportRawHostKey() ?? (object)DBNull.Value);
        command.Parameters.AddWithValue(
            "$created_at_ms",
            ToUnixMilliseconds(connectionProfile.CreatedAtUtc));
        command.Parameters.AddWithValue(
            "$updated_at_ms",
            ToUnixMilliseconds(connectionProfile.UpdatedAtUtc));
        command.Parameters.AddWithValue("$enabled", ToDatabaseBoolean(connectionProfile.Enabled));
        _ = command.ExecuteNonQuery();
    }

    public void SaveTarget(CertificateTarget target)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(target);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        SaveTarget(connection, transaction, target);
        transaction.Commit();
    }

    private static void SaveTarget(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CertificateTarget target)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO targets (
                    target_id,
                    connection_id,
                    display_name,
                    lifecycle_status,
                    created_at_ms,
                    updated_at_ms
                )
                VALUES (
                    $target_id,
                    $connection_id,
                    $display_name,
                    $lifecycle_status,
                    $created_at_ms,
                    $updated_at_ms
                )
                ON CONFLICT(target_id) DO UPDATE SET
                    connection_id = excluded.connection_id,
                    display_name = excluded.display_name,
                    lifecycle_status = excluded.lifecycle_status,
                    updated_at_ms = excluded.updated_at_ms;
                """;
            command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(target.Id.Value));
            command.Parameters.AddWithValue(
                "$connection_id",
                ToDatabaseGuid(target.ConnectionId.Value));
            command.Parameters.AddWithValue("$display_name", target.DisplayName);
            command.Parameters.AddWithValue(
                "$lifecycle_status",
                target.LifecycleStatus.ToString());
            command.Parameters.AddWithValue(
                "$created_at_ms",
                ToUnixMilliseconds(target.CreatedAtUtc));
            command.Parameters.AddWithValue(
                "$updated_at_ms",
                ToUnixMilliseconds(target.UpdatedAtUtc));
            _ = command.ExecuteNonQuery();
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                DELETE FROM target_names
                WHERE target_id = $target_id;
                """;
            command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(target.Id.Value));
            _ = command.ExecuteNonQuery();
        }

        foreach (var name in target.Names)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO target_names (target_id, name_ascii, is_primary)
                VALUES ($target_id, $name_ascii, $is_primary);
                """;
            command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(target.Id.Value));
            command.Parameters.AddWithValue("$name_ascii", name.Value);
            command.Parameters.AddWithValue(
                "$is_primary",
                ToDatabaseBoolean(name == target.PrimaryName));
            _ = command.ExecuteNonQuery();
        }

    }

    public void SaveDeploymentPlan(DeploymentPlan deploymentPlan)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(deploymentPlan);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        SaveDeploymentPlan(connection, transaction, deploymentPlan);
        transaction.Commit();
    }

    private static void SaveDeploymentPlan(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeploymentPlan deploymentPlan)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO deployment_plans (
                deployment_plan_id,
                target_id,
                kind,
                challenge_webroot,
                remote_incoming_root,
                certificate_path,
                private_key_path,
                created_at_ms,
                updated_at_ms,
                enabled
            )
            VALUES (
                $deployment_plan_id,
                $target_id,
                $kind,
                $challenge_webroot,
                $remote_incoming_root,
                $certificate_path,
                $private_key_path,
                $created_at_ms,
                $updated_at_ms,
                $enabled
            )
            ON CONFLICT(deployment_plan_id) DO UPDATE SET
                target_id = excluded.target_id,
                kind = excluded.kind,
                challenge_webroot = excluded.challenge_webroot,
                remote_incoming_root = excluded.remote_incoming_root,
                certificate_path = excluded.certificate_path,
                private_key_path = excluded.private_key_path,
                updated_at_ms = excluded.updated_at_ms,
                enabled = excluded.enabled;
            """;
        command.Parameters.AddWithValue(
            "$deployment_plan_id",
            ToDatabaseGuid(deploymentPlan.Id.Value));
        command.Parameters.AddWithValue(
            "$target_id",
            ToDatabaseGuid(deploymentPlan.TargetId.Value));
        command.Parameters.AddWithValue("$kind", deploymentPlan.Kind.ToString());
        command.Parameters.AddWithValue(
            "$challenge_webroot",
            deploymentPlan.ChallengeWebroot.Value);
        command.Parameters.AddWithValue(
            "$remote_incoming_root",
            deploymentPlan.RemoteIncomingRoot.HasValue
                ? deploymentPlan.RemoteIncomingRoot.Value.Value
                : DBNull.Value);
        command.Parameters.AddWithValue(
            "$certificate_path",
            deploymentPlan.CertificatePath.Value);
        command.Parameters.AddWithValue(
            "$private_key_path",
            deploymentPlan.PrivateKeyPath.Value);
        command.Parameters.AddWithValue(
            "$created_at_ms",
            ToUnixMilliseconds(deploymentPlan.CreatedAtUtc));
        command.Parameters.AddWithValue(
            "$updated_at_ms",
            ToUnixMilliseconds(deploymentPlan.UpdatedAtUtc));
        command.Parameters.AddWithValue("$enabled", ToDatabaseBoolean(deploymentPlan.Enabled));
        _ = command.ExecuteNonQuery();
    }

    public void SaveRenewalPolicy(RenewalPolicy renewalPolicy)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(renewalPolicy);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        SaveRenewalPolicy(connection, transaction, renewalPolicy);
        transaction.Commit();
    }

    private static void SaveRenewalPolicy(
        SqliteConnection connection,
        SqliteTransaction transaction,
        RenewalPolicy renewalPolicy)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO renewal_policies (
                renewal_policy_id,
                target_id,
                renew_before_days,
                check_interval_minutes,
                enabled,
                next_due_at_ms,
                created_at_ms,
                updated_at_ms
            )
            VALUES (
                $renewal_policy_id,
                $target_id,
                $renew_before_days,
                $check_interval_minutes,
                $enabled,
                $next_due_at_ms,
                $created_at_ms,
                $updated_at_ms
            )
            ON CONFLICT(renewal_policy_id) DO UPDATE SET
                target_id = excluded.target_id,
                renew_before_days = excluded.renew_before_days,
                check_interval_minutes = excluded.check_interval_minutes,
                enabled = excluded.enabled,
                next_due_at_ms = excluded.next_due_at_ms,
                updated_at_ms = excluded.updated_at_ms;
            """;
        command.Parameters.AddWithValue(
            "$renewal_policy_id",
            ToDatabaseGuid(renewalPolicy.Id.Value));
        command.Parameters.AddWithValue(
            "$target_id",
            ToDatabaseGuid(renewalPolicy.TargetId.Value));
        command.Parameters.AddWithValue("$renew_before_days", renewalPolicy.RenewBeforeDays);
        command.Parameters.AddWithValue(
            "$check_interval_minutes",
            renewalPolicy.CheckIntervalMinutes);
        command.Parameters.AddWithValue("$enabled", ToDatabaseBoolean(renewalPolicy.Enabled));
        command.Parameters.AddWithValue(
            "$next_due_at_ms",
            renewalPolicy.NextDueAtUtc.HasValue
                ? ToUnixMilliseconds(renewalPolicy.NextDueAtUtc.Value)
                : DBNull.Value);
        command.Parameters.AddWithValue(
            "$created_at_ms",
            ToUnixMilliseconds(renewalPolicy.CreatedAtUtc));
        command.Parameters.AddWithValue(
            "$updated_at_ms",
            ToUnixMilliseconds(renewalPolicy.UpdatedAtUtc));
        _ = command.ExecuteNonQuery();
    }

    public void SaveTargetIssuanceProfile(TargetIssuanceProfile issuanceProfile)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(issuanceProfile);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        SaveTargetIssuanceProfile(connection, transaction, issuanceProfile);
        transaction.Commit();
    }

    private static void SaveTargetIssuanceProfile(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TargetIssuanceProfile issuanceProfile)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO target_issuance_profiles (
                target_id,
                directory_uri,
                contact_uri,
                terms_accepted,
                terms_accepted_at_ms,
                account_key_secret_reference,
                account_uri,
                created_at_ms,
                updated_at_ms
            )
            VALUES (
                $target_id,
                $directory_uri,
                $contact_uri,
                $terms_accepted,
                $terms_accepted_at_ms,
                $account_key_secret_reference,
                $account_uri,
                $created_at_ms,
                $updated_at_ms
            )
            ON CONFLICT(target_id) DO UPDATE SET
                directory_uri = excluded.directory_uri,
                contact_uri = excluded.contact_uri,
                terms_accepted = excluded.terms_accepted,
                terms_accepted_at_ms = excluded.terms_accepted_at_ms,
                account_key_secret_reference = excluded.account_key_secret_reference,
                account_uri = excluded.account_uri,
                updated_at_ms = excluded.updated_at_ms;
            """;
        command.Parameters.AddWithValue(
            "$target_id",
            ToDatabaseGuid(issuanceProfile.TargetId.Value));
        command.Parameters.AddWithValue(
            "$directory_uri",
            issuanceProfile.DirectoryUri.AbsoluteUri);
        command.Parameters.AddWithValue("$contact_uri", issuanceProfile.Contact.Value);
        command.Parameters.AddWithValue(
            "$terms_accepted",
            ToDatabaseBoolean(issuanceProfile.TermsAccepted));
        command.Parameters.AddWithValue(
            "$terms_accepted_at_ms",
            issuanceProfile.TermsAcceptedAtUtc.HasValue
                ? ToUnixMilliseconds(issuanceProfile.TermsAcceptedAtUtc.Value)
                : DBNull.Value);
        command.Parameters.AddWithValue(
            "$account_key_secret_reference",
            issuanceProfile.AccountKeySecretReference);
        command.Parameters.AddWithValue(
            "$account_uri",
            issuanceProfile.AccountUri?.AbsoluteUri ?? (object)DBNull.Value);
        command.Parameters.AddWithValue(
            "$created_at_ms",
            ToUnixMilliseconds(issuanceProfile.CreatedAtUtc));
        command.Parameters.AddWithValue(
            "$updated_at_ms",
            ToUnixMilliseconds(issuanceProfile.UpdatedAtUtc));
        _ = command.ExecuteNonQuery();
    }

    public void SaveEnrollment(TargetEnrollment enrollment)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(enrollment);
        var identitySha256 = ComputeEnrollmentIdentity(enrollment);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existingIdentity = ReadEnrollmentIdentity(
            connection,
            transaction,
            enrollment.Id);
        if (existingIdentity is not null &&
            (!string.Equals(
                    existingIdentity.Value.TargetId,
                    ToDatabaseGuid(enrollment.Target.Id.Value),
                    StringComparison.Ordinal) ||
                !string.Equals(
                    existingIdentity.Value.IdentitySha256,
                    identitySha256,
                    StringComparison.Ordinal)))
        {
            throw new ProductionEnrollmentConflictException();
        }

        if (existingIdentity is null)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                SELECT enrollment_id
                FROM enrollments
                WHERE target_id = $target_id;
                """;
            command.Parameters.AddWithValue(
                "$target_id",
                ToDatabaseGuid(enrollment.Target.Id.Value));
            if (command.ExecuteScalar() is not null)
            {
                throw new ProductionEnrollmentConflictException();
            }
        }

        if (!PersistedConnectionIdentityMatches(
                connection,
                transaction,
                enrollment.Connection))
        {
            throw new ProductionEnrollmentConflictException();
        }

        SaveConnection(connection, transaction, enrollment.Connection);
        SaveTarget(connection, transaction, enrollment.Target);
        SaveDeploymentPlan(connection, transaction, enrollment.DeploymentPlan);
        SaveRenewalPolicy(connection, transaction, enrollment.RenewalPolicy);
        SaveTargetIssuanceProfile(connection, transaction, enrollment.IssuanceProfile);
        if (existingIdentity is null)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO enrollments (
                    enrollment_id,
                    target_id,
                    connection_id,
                    deployment_plan_id,
                    renewal_policy_id,
                    identity_sha256,
                    enrolled_at_ms
                )
                VALUES (
                    $enrollment_id,
                    $target_id,
                    $connection_id,
                    $deployment_plan_id,
                    $renewal_policy_id,
                    $identity_sha256,
                    $enrolled_at_ms
                );
                """;
            command.Parameters.AddWithValue(
                "$enrollment_id",
                ToDatabaseGuid(enrollment.Id.Value));
            command.Parameters.AddWithValue(
                "$target_id",
                ToDatabaseGuid(enrollment.Target.Id.Value));
            command.Parameters.AddWithValue(
                "$connection_id",
                ToDatabaseGuid(enrollment.Connection.Id.Value));
            command.Parameters.AddWithValue(
                "$deployment_plan_id",
                ToDatabaseGuid(enrollment.DeploymentPlan.Id.Value));
            command.Parameters.AddWithValue(
                "$renewal_policy_id",
                ToDatabaseGuid(enrollment.RenewalPolicy.Id.Value));
            command.Parameters.AddWithValue("$identity_sha256", identitySha256);
            command.Parameters.AddWithValue(
                "$enrolled_at_ms",
                ToUnixMilliseconds(enrollment.EnrolledAtUtc));
            _ = command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    public AcmeAccountRecord CreateOrGetAcmeAccount(AcmeAccountRecord account)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(account);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindAcmeAccountByDirectoryAndSecretReference(
            connection,
            transaction,
            account.DirectoryUri.AbsoluteUri,
            account.KeySecretReference);
        if (existing is not null)
        {
            transaction.Commit();
            return existing;
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO acme_accounts (
                    acme_account_id,
                    directory_uri,
                    account_uri,
                    contact_email,
                    key_secret_reference,
                    status,
                    created_at_ms,
                    updated_at_ms
                )
                VALUES (
                    $acme_account_id,
                    $directory_uri,
                    $account_uri,
                    $contact_email,
                    $key_secret_reference,
                    $status,
                    $created_at_ms,
                    $updated_at_ms
                );
                """;
            command.Parameters.AddWithValue(
                "$acme_account_id",
                ToDatabaseGuid(account.Id.Value));
            command.Parameters.AddWithValue(
                "$directory_uri",
                account.DirectoryUri.AbsoluteUri);
            command.Parameters.AddWithValue(
                "$account_uri",
                account.AccountUri?.AbsoluteUri ?? (object)DBNull.Value);
            command.Parameters.AddWithValue(
                "$contact_email",
                account.ContactEmail ?? (object)DBNull.Value);
            command.Parameters.AddWithValue(
                "$key_secret_reference",
                account.KeySecretReference);
            command.Parameters.AddWithValue("$status", account.Status.ToString());
            command.Parameters.AddWithValue(
                "$created_at_ms",
                ToUnixMilliseconds(account.CreatedAtUtc));
            command.Parameters.AddWithValue(
                "$updated_at_ms",
                ToUnixMilliseconds(account.UpdatedAtUtc));
            _ = command.ExecuteNonQuery();
        }

        var result = FindAcmeAccountByDirectoryAndSecretReference(
            connection,
            transaction,
            account.DirectoryUri.AbsoluteUri,
            account.KeySecretReference)
            ?? throw new InvalidOperationException(
                "The ACME account could not be read after creation.");
        transaction.Commit();
        return result;
    }

    public ConnectionProfile? FindConnection(ConnectionId connectionId)
    {
        EnsureInitialized();
        ValidateGuid(connectionId.Value, nameof(connectionId));
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT {ConnectionProjectionColumns}
            FROM connections
            WHERE connection_id = $connection_id;
            """;
        command.Parameters.AddWithValue(
            "$connection_id",
            ToDatabaseGuid(connectionId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadConnection(reader) : null;
    }

    public CertificateTarget? FindTarget(TargetId targetId)
    {
        EnsureInitialized();
        ValidateGuid(targetId.Value, nameof(targetId));
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction();
        ConnectionId connectionId;
        string displayName;
        TargetLifecycleStatus lifecycleStatus;
        DateTimeOffset createdAtUtc;
        DateTimeOffset updatedAtUtc;
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                SELECT
                    connection_id,
                    display_name,
                    lifecycle_status,
                    created_at_ms,
                    updated_at_ms
                FROM targets
                WHERE target_id = $target_id;
                """;
            command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(targetId.Value));
            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                transaction.Commit();
                return null;
            }

            connectionId = new ConnectionId(ReadDatabaseGuid(reader.GetString(0)));
            displayName = reader.GetString(1);
            lifecycleStatus = ParseEnum<TargetLifecycleStatus>(
                reader.GetString(2),
                "target lifecycle status");
            createdAtUtc = FromUnixMilliseconds(reader.GetInt64(3));
            updatedAtUtc = FromUnixMilliseconds(reader.GetInt64(4));
        }

        TargetDnsName? primaryName = null;
        var alternativeNames = new List<TargetDnsName>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                SELECT name_ascii, is_primary
                FROM target_names
                WHERE target_id = $target_id
                ORDER BY is_primary DESC, name_ascii;
                """;
            command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(targetId.Value));
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var name = new TargetDnsName(reader.GetString(0));
                if (ReadDatabaseBoolean(reader.GetInt64(1)))
                {
                    if (primaryName.HasValue)
                    {
                        throw new InvalidOperationException(
                            "The persisted target has more than one primary name.");
                    }

                    primaryName = name;
                }
                else
                {
                    alternativeNames.Add(name);
                }
            }
        }

        if (!primaryName.HasValue)
        {
            throw new InvalidOperationException(
                "The persisted target does not have a primary name.");
        }

        var target = new CertificateTarget(
            targetId,
            connectionId,
            displayName,
            primaryName.Value,
            alternativeNames,
            lifecycleStatus,
            createdAtUtc,
            updatedAtUtc);
        transaction.Commit();
        return target;
    }

    public IReadOnlyList<CertificateTarget> ListTargets(
        int maximumCount,
        TargetId? afterTargetId = null)
    {
        EnsureInitialized();
        if (maximumCount is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumCount),
                maximumCount,
                "A target page must contain between 1 and 500 records.");
        }

        if (afterTargetId.HasValue)
        {
            ValidateGuid(afterTargetId.Value.Value, nameof(afterTargetId));
        }

        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = afterTargetId.HasValue
            ?
            """
            SELECT target_id
            FROM targets
            WHERE target_id > $after_target_id
            ORDER BY target_id
            LIMIT $maximum_count;
            """
            :
            """
            SELECT target_id
            FROM targets
            ORDER BY target_id
            LIMIT $maximum_count;
            """;
        if (afterTargetId.HasValue)
        {
            command.Parameters.AddWithValue(
                "$after_target_id",
                ToDatabaseGuid(afterTargetId.Value.Value));
        }

        command.Parameters.AddWithValue("$maximum_count", maximumCount);
        var targetIds = new List<TargetId>(maximumCount);
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                targetIds.Add(new TargetId(ReadDatabaseGuid(reader.GetString(0))));
            }
        }

        var targets = new List<CertificateTarget>(targetIds.Count);
        foreach (var targetId in targetIds)
        {
            targets.Add(
                FindTarget(targetId)
                ?? throw new InvalidOperationException(
                    "A target disappeared while its bounded page was being read."));
        }

        return targets.AsReadOnly();
    }

    public DeploymentPlan? FindDeploymentPlan(DeploymentPlanId deploymentPlanId)
    {
        EnsureInitialized();
        ValidateGuid(deploymentPlanId.Value, nameof(deploymentPlanId));
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT {DeploymentPlanProjectionColumns}
            FROM deployment_plans
            WHERE deployment_plan_id = $deployment_plan_id;
            """;
        command.Parameters.AddWithValue(
            "$deployment_plan_id",
            ToDatabaseGuid(deploymentPlanId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadDeploymentPlan(reader) : null;
    }

    public DeploymentPlan? FindEnabledDeploymentPlan(TargetId targetId)
    {
        EnsureInitialized();
        ValidateGuid(targetId.Value, nameof(targetId));
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT {DeploymentPlanProjectionColumns}
            FROM deployment_plans
            WHERE target_id = $target_id
              AND enabled = 1;
            """;
        command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(targetId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadDeploymentPlan(reader) : null;
    }

    public RenewalPolicy? FindRenewalPolicy(RenewalPolicyId renewalPolicyId)
    {
        EnsureInitialized();
        ValidateGuid(renewalPolicyId.Value, nameof(renewalPolicyId));
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT {RenewalPolicyProjectionColumns}
            FROM renewal_policies
            WHERE renewal_policy_id = $renewal_policy_id;
            """;
        command.Parameters.AddWithValue(
            "$renewal_policy_id",
            ToDatabaseGuid(renewalPolicyId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadRenewalPolicy(reader) : null;
    }

    public RenewalPolicy? FindEnabledRenewalPolicy(TargetId targetId)
    {
        EnsureInitialized();
        ValidateGuid(targetId.Value, nameof(targetId));
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT {RenewalPolicyProjectionColumns}
            FROM renewal_policies
            WHERE target_id = $target_id
              AND enabled = 1;
            """;
        command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(targetId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadRenewalPolicy(reader) : null;
    }

    public RenewalPolicy? FindRenewalPolicyByTarget(TargetId targetId)
    {
        EnsureInitialized();
        ValidateGuid(targetId.Value, nameof(targetId));
        using var connection = database.OpenConnection();
        return FindRenewalPolicyByTarget(connection, transaction: null, targetId);
    }

    public TargetIssuanceProfile? FindTargetIssuanceProfile(TargetId targetId)
    {
        EnsureInitialized();
        ValidateGuid(targetId.Value, nameof(targetId));
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT
                target_id,
                directory_uri,
                contact_uri,
                terms_accepted,
                terms_accepted_at_ms,
                account_key_secret_reference,
                account_uri,
                created_at_ms,
                updated_at_ms
            FROM target_issuance_profiles
            WHERE target_id = $target_id;
            """;
        command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(targetId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadTargetIssuanceProfile(reader) : null;
    }

    public AcmeAccountRecord? FindPreferredValidAcmeAccount(Uri directoryUri)
    {
        EnsureInitialized();
        var normalizedDirectoryUri = NormalizeHttpsUri(directoryUri, nameof(directoryUri));
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT
                acme_account_id,
                directory_uri,
                account_uri,
                contact_email,
                key_secret_reference,
                status,
                created_at_ms,
                updated_at_ms
            FROM acme_accounts
            WHERE directory_uri = $directory_uri
              AND status = 'Valid'
              AND account_uri IS NOT NULL
            ORDER BY updated_at_ms DESC, created_at_ms DESC, acme_account_id
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$directory_uri", normalizedDirectoryUri);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadAcmeAccount(reader) : null;
    }

    public AcmeAccountRecord? FindAcmeAccount(
        Uri directoryUri,
        string keySecretReference)
    {
        EnsureInitialized();
        var normalizedDirectoryUri = NormalizeHttpsUri(directoryUri, nameof(directoryUri));
        ValidateSecretReference(keySecretReference, nameof(keySecretReference));
        using var connection = database.OpenConnection();
        return FindAcmeAccountByDirectoryAndSecretReference(
            connection,
            transaction: null,
            normalizedDirectoryUri,
            keySecretReference);
    }

    public AcmeAccountRecord UpdateAcmeAccountRegistration(
        AcmeAccountId accountId,
        AcmeAccountStatus expectedStatus,
        Uri? accountUri,
        AcmeAccountStatus newStatus,
        DateTimeOffset updatedAtUtc)
    {
        EnsureInitialized();
        ValidateGuid(accountId.Value, nameof(accountId));
        if (!Enum.IsDefined(expectedStatus))
        {
            throw new ArgumentOutOfRangeException(nameof(expectedStatus));
        }

        if (!Enum.IsDefined(newStatus))
        {
            throw new ArgumentOutOfRangeException(nameof(newStatus));
        }

        var normalizedAccountUri = accountUri is null
            ? null
            : NormalizeHttpsUri(accountUri, nameof(accountUri));
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindAcmeAccount(connection, transaction, accountId)
            ?? throw new KeyNotFoundException("The ACME account does not exist.");
        if (existing.Status == newStatus &&
            string.Equals(
                existing.AccountUri?.AbsoluteUri,
                normalizedAccountUri,
                StringComparison.Ordinal))
        {
            transaction.Commit();
            return existing;
        }

        if (existing.Status != expectedStatus)
        {
            throw new ProductionAcmeAccountStateConflictException();
        }

        if (updatedAtUtc.ToUniversalTime() < existing.UpdatedAtUtc)
        {
            throw new ArgumentException(
                "The account update timestamp cannot precede the persisted account timestamp.",
                nameof(updatedAtUtc));
        }

        _ = new AcmeAccountRecord(
            existing.Id,
            existing.DirectoryUri,
            accountUri,
            existing.ContactEmail,
            existing.KeySecretReference,
            newStatus,
            existing.CreatedAtUtc,
            updatedAtUtc);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE acme_accounts
                SET account_uri = $account_uri,
                    status = $new_status,
                    updated_at_ms = $updated_at_ms
                WHERE acme_account_id = $acme_account_id
                  AND status = $expected_status;
                """;
            command.Parameters.AddWithValue(
                "$account_uri",
                normalizedAccountUri ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("$new_status", newStatus.ToString());
            command.Parameters.AddWithValue(
                "$updated_at_ms",
                ToUnixMilliseconds(updatedAtUtc));
            command.Parameters.AddWithValue(
                "$acme_account_id",
                ToDatabaseGuid(accountId.Value));
            command.Parameters.AddWithValue(
                "$expected_status",
                expectedStatus.ToString());
            if (command.ExecuteNonQuery() != 1)
            {
                throw new ProductionAcmeAccountStateConflictException();
            }
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE target_issuance_profiles
                SET account_uri = $account_uri,
                    updated_at_ms = $updated_at_ms
                WHERE directory_uri = $directory_uri
                  AND account_key_secret_reference = $key_secret_reference
                  AND updated_at_ms <= $updated_at_ms;
                """;
            command.Parameters.AddWithValue(
                "$account_uri",
                normalizedAccountUri ?? (object)DBNull.Value);
            command.Parameters.AddWithValue(
                "$updated_at_ms",
                ToUnixMilliseconds(updatedAtUtc));
            command.Parameters.AddWithValue(
                "$directory_uri",
                existing.DirectoryUri.AbsoluteUri);
            command.Parameters.AddWithValue(
                "$key_secret_reference",
                existing.KeySecretReference);
            _ = command.ExecuteNonQuery();
        }

        var updated = FindAcmeAccount(connection, transaction, accountId)
            ?? throw new InvalidOperationException(
                "The ACME account could not be read after registration update.");
        transaction.Commit();
        return updated;
    }

    public RenewalOperation CreateOrGetOperation(RenewalOperation operation)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(operation);
        if (operation.Status != OperationStatus.Queued)
        {
            throw new ArgumentException(
                "A new production operation must be queued.",
                nameof(operation));
        }

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindOperationByRequestKey(
            connection,
            transaction,
            operation.RequestKey);
        if (existing is not null)
        {
            if (existing.TargetId != operation.TargetId ||
                existing.Kind != operation.Kind)
            {
                throw new ProductionIdempotencyConflictException();
            }

            transaction.Commit();
            return existing;
        }

        EnsureNoActiveOperation(connection, transaction, operation.TargetId);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO operations (
                    operation_id,
                    target_id,
                    request_key,
                    kind,
                    status,
                    requested_at_ms,
                    updated_at_ms
                )
                VALUES (
                    $operation_id,
                    $target_id,
                    $request_key,
                    'Renewal',
                    'Queued',
                    $requested_at_ms,
                    $updated_at_ms
                );
                """;
            command.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(operation.Id.Value));
            command.Parameters.AddWithValue(
                "$target_id",
                ToDatabaseGuid(operation.TargetId.Value));
            command.Parameters.AddWithValue("$request_key", operation.RequestKey);
            command.Parameters.AddWithValue(
                "$requested_at_ms",
                ToUnixMilliseconds(operation.RequestedAtUtc));
            command.Parameters.AddWithValue(
                "$updated_at_ms",
                ToUnixMilliseconds(operation.UpdatedAtUtc));
            _ = command.ExecuteNonQuery();
        }

        var result = FindOperationByRequestKey(
            connection,
            transaction,
            operation.RequestKey)
            ?? throw new InvalidOperationException(
                "The production operation could not be read after creation.");
        transaction.Commit();
        return result;
    }

    public RenewalOperation? TryStartOperation(
        OperationId operationId,
        Guid executionEpoch,
        DateTimeOffset startedAtUtc)
    {
        EnsureInitialized();
        ValidateGuid(operationId.Value, nameof(operationId));
        ValidateGuid(executionEpoch, nameof(executionEpoch));
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindOperation(connection, transaction, operationId);
        if (existing is null)
        {
            transaction.Commit();
            return null;
        }

        if (existing.Status == OperationStatus.Running &&
            existing.ExecutionEpoch == executionEpoch)
        {
            transaction.Commit();
            return existing;
        }

        if (existing.Status != OperationStatus.Queued)
        {
            transaction.Commit();
            return null;
        }

        if (startedAtUtc.ToUniversalTime() < existing.UpdatedAtUtc)
        {
            throw new ArgumentException(
                "The start timestamp cannot precede the persisted operation timestamp.",
                nameof(startedAtUtc));
        }

        _ = new RenewalOperation(
            existing.Id,
            existing.TargetId,
            existing.RequestKey,
            OperationStatus.Running,
            existing.RequestedAtUtc,
            startedAtUtc,
            startedAtUtc,
            completedAtUtc: null,
            executionEpoch,
            failureCode: null);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE operations
                SET status = 'Running',
                    updated_at_ms = $started_at_ms,
                    started_at_ms = $started_at_ms,
                    execution_epoch = $execution_epoch,
                    failure_code = NULL
                WHERE operation_id = $operation_id
                  AND status = 'Queued'
                  AND execution_epoch IS NULL;
                """;
            command.Parameters.AddWithValue(
                "$started_at_ms",
                ToUnixMilliseconds(startedAtUtc));
            command.Parameters.AddWithValue(
                "$execution_epoch",
                ToDatabaseGuid(executionEpoch));
            command.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(operationId.Value));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new ProductionOperationStateConflictException();
            }
        }

        var started = FindOperation(connection, transaction, operationId)
            ?? throw new InvalidOperationException(
                "The production operation could not be read after it was started.");
        transaction.Commit();
        return started;
    }

    public RenewalOperation TransitionOwnedOperationStatus(
        OperationId operationId,
        Guid executionEpoch,
        OperationStatus expectedStatus,
        OperationStatus newStatus,
        DateTimeOffset updatedAtUtc,
        string? failureCode = null)
    {
        EnsureInitialized();
        ValidateGuid(operationId.Value, nameof(operationId));
        ValidateGuid(executionEpoch, nameof(executionEpoch));
        if (!IsOwnedActiveStatus(expectedStatus) || !IsOwnedActiveStatus(newStatus))
        {
            throw new ArgumentOutOfRangeException(
                nameof(newStatus),
                newStatus,
                "Owned status transitions are limited to running, blocked, and rollback-required operations.");
        }

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindOperation(connection, transaction, operationId)
            ?? throw new KeyNotFoundException("The production operation does not exist.");
        if (existing.Status == newStatus &&
            existing.ExecutionEpoch == executionEpoch &&
            string.Equals(existing.FailureCode, failureCode, StringComparison.Ordinal))
        {
            transaction.Commit();
            return existing;
        }

        if (existing.Status != expectedStatus ||
            existing.ExecutionEpoch != executionEpoch)
        {
            throw new ProductionOperationStateConflictException();
        }

        if (updatedAtUtc.ToUniversalTime() < existing.UpdatedAtUtc)
        {
            throw new ArgumentException(
                "The transition timestamp cannot precede the persisted operation timestamp.",
                nameof(updatedAtUtc));
        }

        _ = new RenewalOperation(
            existing.Id,
            existing.TargetId,
            existing.RequestKey,
            newStatus,
            existing.RequestedAtUtc,
            updatedAtUtc,
            existing.StartedAtUtc,
            completedAtUtc: null,
            executionEpoch,
            failureCode);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE operations
                SET status = $new_status,
                    updated_at_ms = $updated_at_ms,
                    failure_code = $failure_code
                WHERE operation_id = $operation_id
                  AND status = $expected_status
                  AND execution_epoch = $execution_epoch;
                """;
            command.Parameters.AddWithValue("$new_status", newStatus.ToString());
            command.Parameters.AddWithValue(
                "$updated_at_ms",
                ToUnixMilliseconds(updatedAtUtc));
            command.Parameters.AddWithValue(
                "$failure_code",
                failureCode ?? (object)DBNull.Value);
            command.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(operationId.Value));
            command.Parameters.AddWithValue(
                "$expected_status",
                expectedStatus.ToString());
            command.Parameters.AddWithValue(
                "$execution_epoch",
                ToDatabaseGuid(executionEpoch));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new ProductionOperationStateConflictException();
            }
        }

        var transitioned = FindOperation(connection, transaction, operationId)
            ?? throw new InvalidOperationException(
                "The production operation could not be read after its state transition.");
        transaction.Commit();
        return transitioned;
    }

    public OperationEvidence AppendOperationEvidence(
        OperationId operationId,
        OperationEvidenceKind kind,
        string? stage,
        OperationEvidenceOutcome outcome,
        DateTimeOffset recordedAtUtc,
        string code,
        string description)
    {
        EnsureInitialized();
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var operation = FindOperation(connection, transaction, operationId)
            ?? throw new KeyNotFoundException("The production operation does not exist.");

        long sequence;
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                SELECT COALESCE(MAX(sequence), 0) + 1
                FROM operation_evidence
                WHERE operation_id = $operation_id;
                """;
            command.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(operation.Id.Value));
            sequence = Convert.ToInt64(
                command.ExecuteScalar(),
                CultureInfo.InvariantCulture);
        }

        var evidence = new OperationEvidence(
            operationId,
            sequence,
            kind,
            stage,
            outcome,
            recordedAtUtc,
            code,
            description);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO operation_evidence (
                    operation_id,
                    sequence,
                    kind,
                    stage,
                    outcome,
                    recorded_at_ms,
                    code,
                    description
                )
                VALUES (
                    $operation_id,
                    $sequence,
                    $kind,
                    $stage,
                    $outcome,
                    $recorded_at_ms,
                    $code,
                    $description
                );
                """;
            command.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(evidence.OperationId.Value));
            command.Parameters.AddWithValue("$sequence", evidence.Sequence);
            command.Parameters.AddWithValue("$kind", evidence.Kind.ToString());
            command.Parameters.AddWithValue("$stage", evidence.Stage ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("$outcome", evidence.Outcome.ToString());
            command.Parameters.AddWithValue(
                "$recorded_at_ms",
                ToUnixMilliseconds(evidence.RecordedAtUtc));
            command.Parameters.AddWithValue("$code", evidence.Code);
            command.Parameters.AddWithValue("$description", evidence.Description);
            _ = command.ExecuteNonQuery();
        }

        transaction.Commit();
        return evidence;
    }

    public AuditEvent AppendAuditEvent(
        AuditEventId auditEventId,
        OperationId? operationId,
        TargetId? targetId,
        string actorSid,
        string eventType,
        DateTimeOffset occurredAtUtc,
        string code,
        string description)
    {
        EnsureInitialized();
        var proposed = new AuditEvent(
            auditEventId,
            sequence: 1,
            operationId,
            targetId,
            actorSid,
            eventType,
            occurredAtUtc,
            code,
            description);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindAuditEvent(connection, transaction, auditEventId);
        if (existing is not null)
        {
            if (!AuditEventMatches(existing, proposed))
            {
                throw new ProductionAuditEventConflictException();
            }

            transaction.Commit();
            return existing;
        }

        if (operationId.HasValue)
        {
            var operation = FindOperation(connection, transaction, operationId.Value)
                ?? throw new KeyNotFoundException(
                    "The audit event references an operation that does not exist.");
            if (targetId.HasValue && operation.TargetId != targetId.Value)
            {
                throw new ArgumentException(
                    "The audit event operation does not belong to the selected target.",
                    nameof(targetId));
            }
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO audit_events (
                    audit_event_id,
                    operation_id,
                    target_id,
                    actor_sid,
                    event_type,
                    occurred_at_ms,
                    code,
                    description
                )
                VALUES (
                    $audit_event_id,
                    $operation_id,
                    $target_id,
                    $actor_sid,
                    $event_type,
                    $occurred_at_ms,
                    $code,
                    $description
                );
                """;
            command.Parameters.AddWithValue(
                "$audit_event_id",
                ToDatabaseGuid(auditEventId.Value));
            command.Parameters.AddWithValue(
                "$operation_id",
                operationId.HasValue
                    ? ToDatabaseGuid(operationId.Value.Value)
                    : DBNull.Value);
            command.Parameters.AddWithValue(
                "$target_id",
                targetId.HasValue
                    ? ToDatabaseGuid(targetId.Value.Value)
                    : DBNull.Value);
            command.Parameters.AddWithValue("$actor_sid", proposed.ActorSid);
            command.Parameters.AddWithValue("$event_type", proposed.EventType);
            command.Parameters.AddWithValue(
                "$occurred_at_ms",
                ToUnixMilliseconds(proposed.OccurredAtUtc));
            command.Parameters.AddWithValue("$code", proposed.Code);
            command.Parameters.AddWithValue("$description", proposed.Description);
            _ = command.ExecuteNonQuery();
        }

        var appended = FindAuditEvent(connection, transaction, auditEventId)
            ?? throw new InvalidOperationException(
                "The audit event could not be read after append.");
        transaction.Commit();
        return appended;
    }

    public IReadOnlyList<AuditEvent> ReadAuditEvents(
        int maximumCount,
        long afterSequence = 0)
    {
        EnsureInitialized();
        if (maximumCount is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumCount),
                maximumCount,
                "An audit-event page must contain between 1 and 500 records.");
        }

        ArgumentOutOfRangeException.ThrowIfNegative(afterSequence);
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT {AuditEventProjectionColumns}
            FROM audit_events
            WHERE event_sequence > $after_sequence
            ORDER BY event_sequence
            LIMIT $maximum_count;
            """;
        command.Parameters.AddWithValue("$after_sequence", afterSequence);
        command.Parameters.AddWithValue("$maximum_count", maximumCount);
        using var reader = command.ExecuteReader();
        var events = new List<AuditEvent>(maximumCount);
        while (reader.Read())
        {
            events.Add(ReadAuditEvent(reader));
        }

        return events.AsReadOnly();
    }

    public OperationIntent CreateOrGetOperationIntent(OperationIntent operationIntent)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(operationIntent);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindOperationIntentByKey(
            connection,
            transaction,
            operationIntent.IdempotencyKey);
        if (existing is not null)
        {
            if (existing.OperationId != operationIntent.OperationId ||
                existing.Sequence != operationIntent.Sequence ||
                existing.Kind != operationIntent.Kind ||
                !string.Equals(
                    existing.RemotePath,
                    operationIntent.RemotePath,
                    StringComparison.Ordinal))
            {
                throw new ProductionIdempotencyConflictException();
            }

            transaction.Commit();
            return existing;
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO operation_intents (
                    operation_intent_id,
                    operation_id,
                    sequence,
                    kind,
                    idempotency_key,
                    status,
                    recorded_at_ms,
                    applied_at_ms,
                    remote_path
                )
                VALUES (
                    $operation_intent_id,
                    $operation_id,
                    $sequence,
                    $kind,
                    $idempotency_key,
                    $status,
                    $recorded_at_ms,
                    $applied_at_ms,
                    $remote_path
                );
                """;
            command.Parameters.AddWithValue(
                "$operation_intent_id",
                ToDatabaseGuid(operationIntent.Id.Value));
            command.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(operationIntent.OperationId.Value));
            command.Parameters.AddWithValue("$sequence", operationIntent.Sequence);
            command.Parameters.AddWithValue("$kind", operationIntent.Kind.ToString());
            command.Parameters.AddWithValue(
                "$idempotency_key",
                operationIntent.IdempotencyKey);
            command.Parameters.AddWithValue("$status", operationIntent.Status.ToString());
            command.Parameters.AddWithValue(
                "$recorded_at_ms",
                ToUnixMilliseconds(operationIntent.RecordedAtUtc));
            command.Parameters.AddWithValue(
                "$applied_at_ms",
                operationIntent.AppliedAtUtc.HasValue
                    ? ToUnixMilliseconds(operationIntent.AppliedAtUtc.Value)
                    : DBNull.Value);
            command.Parameters.AddWithValue(
                "$remote_path",
                operationIntent.RemotePath is null
                    ? DBNull.Value
                    : operationIntent.RemotePath);
            _ = command.ExecuteNonQuery();
        }

        var result = FindOperationIntentByKey(
            connection,
            transaction,
            operationIntent.IdempotencyKey)
            ?? throw new InvalidOperationException(
                "The operation intent could not be read after creation.");
        transaction.Commit();
        return result;
    }

    public OperationIntent? FindOperationIntent(OperationIntentId operationIntentId)
    {
        EnsureInitialized();
        ValidateGuid(operationIntentId.Value, nameof(operationIntentId));
        using var connection = database.OpenConnection();
        return FindOperationIntentById(connection, null, operationIntentId);
    }

    public OperationIntent? FindOperationIntentByIdempotencyKey(string idempotencyKey)
    {
        EnsureInitialized();
        ValidateIdempotencyKey(idempotencyKey);
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction();
        var result = FindOperationIntentByKey(connection, transaction, idempotencyKey);
        transaction.Commit();
        return result;
    }

    public IReadOnlyList<OperationIntent> ReadOperationIntents(OperationId operationId)
    {
        EnsureInitialized();
        ValidateGuid(operationId.Value, nameof(operationId));
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT
                operation_intent_id,
                operation_id,
                sequence,
                kind,
                idempotency_key,
                status,
                recorded_at_ms,
                applied_at_ms,
                remote_path
            FROM operation_intents
            WHERE operation_id = $operation_id
            ORDER BY sequence;
            """;
        command.Parameters.AddWithValue(
            "$operation_id",
            ToDatabaseGuid(operationId.Value));
        using var reader = command.ExecuteReader();
        var intents = new List<OperationIntent>();
        while (reader.Read())
        {
            intents.Add(ReadOperationIntent(reader));
        }

        return intents.AsReadOnly();
    }

    public OperationIntent TransitionOwnedOperationIntentStatus(
        OperationIntentId operationIntentId,
        Guid executionEpoch,
        OperationIntentStatus expectedStatus,
        OperationIntentStatus newStatus,
        DateTimeOffset transitionedAtUtc)
    {
        EnsureInitialized();
        ValidateGuid(operationIntentId.Value, nameof(operationIntentId));
        ValidateGuid(executionEpoch, nameof(executionEpoch));
        if (!Enum.IsDefined(expectedStatus))
        {
            throw new ArgumentOutOfRangeException(nameof(expectedStatus));
        }

        if (!Enum.IsDefined(newStatus) ||
            !IsAllowedIntentTransition(expectedStatus, newStatus))
        {
            throw new ArgumentOutOfRangeException(
                nameof(newStatus),
                newStatus,
                "The operation intent status transition is not allowed.");
        }

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindOperationIntentById(
            connection,
            transaction,
            operationIntentId)
            ?? throw new KeyNotFoundException("The operation intent does not exist.");
        var owner = FindOperation(connection, transaction, existing.OperationId);
        if (owner?.ExecutionEpoch != executionEpoch ||
            !IsOwnedActiveStatus(owner.Status))
        {
            throw new ProductionOperationIntentStateConflictException();
        }

        if (existing.Status == newStatus)
        {
            transaction.Commit();
            return existing;
        }

        if (existing.Status != expectedStatus)
        {
            throw new ProductionOperationIntentStateConflictException();
        }

        var appliedAtUtc =
            newStatus is OperationIntentStatus.Applied or OperationIntentStatus.Reconciled
                ? existing.AppliedAtUtc ?? transitionedAtUtc.ToUniversalTime()
                : existing.AppliedAtUtc;
        _ = new OperationIntent(
            existing.Id,
            existing.OperationId,
            existing.Sequence,
            existing.Kind,
            existing.IdempotencyKey,
            newStatus,
            existing.RecordedAtUtc,
            appliedAtUtc,
            existing.RemotePath);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE operation_intents
                SET status = $new_status,
                    applied_at_ms = $applied_at_ms
                WHERE operation_intent_id = $operation_intent_id
                  AND status = $expected_status
                  AND EXISTS (
                      SELECT 1
                      FROM operations
                      WHERE operation_id = operation_intents.operation_id
                        AND execution_epoch = $execution_epoch
                        AND status IN ('Running', 'Blocked', 'RollbackRequired')
                  );
                """;
            command.Parameters.AddWithValue("$new_status", newStatus.ToString());
            command.Parameters.AddWithValue(
                "$applied_at_ms",
                appliedAtUtc.HasValue
                    ? ToUnixMilliseconds(appliedAtUtc.Value)
                    : DBNull.Value);
            command.Parameters.AddWithValue(
                "$operation_intent_id",
                ToDatabaseGuid(operationIntentId.Value));
            command.Parameters.AddWithValue(
                "$expected_status",
                expectedStatus.ToString());
            command.Parameters.AddWithValue(
                "$execution_epoch",
                ToDatabaseGuid(executionEpoch));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new ProductionOperationIntentStateConflictException();
            }
        }

        var transitioned = FindOperationIntentById(
            connection,
            transaction,
            operationIntentId)
            ?? throw new InvalidOperationException(
                "The operation intent could not be read after its state transition.");
        transaction.Commit();
        return transitioned;
    }

    public CertificateArtifact CreateOrGetCertificateArtifact(
        CertificateArtifact certificateArtifact)
    {
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(certificateArtifact);
        if (certificateArtifact.Status != CertificateArtifactStatus.Issued)
        {
            throw new ArgumentException(
                "A new certificate artifact must begin in the issued state.",
                nameof(certificateArtifact));
        }

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindCertificateArtifactByOperation(
            connection,
            transaction,
            certificateArtifact.OperationId);
        if (existing is not null)
        {
            if (existing.CertificateSha256 != certificateArtifact.CertificateSha256 ||
                existing.PublicKeySha256 != certificateArtifact.PublicKeySha256 ||
                !string.Equals(
                    existing.PrivateKeySecretReference,
                    certificateArtifact.PrivateKeySecretReference,
                    StringComparison.Ordinal) ||
                existing.NotBeforeUtc != certificateArtifact.NotBeforeUtc ||
                existing.NotAfterUtc != certificateArtifact.NotAfterUtc)
            {
                throw new ProductionIdempotencyConflictException();
            }

            transaction.Commit();
            return existing;
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO certificate_artifacts (
                    certificate_artifact_id,
                    operation_id,
                    certificate_sha256,
                    public_key_sha256,
                    private_key_secret_reference,
                    not_before_ms,
                    not_after_ms,
                    status,
                    created_at_ms
                )
                VALUES (
                    $certificate_artifact_id,
                    $operation_id,
                    $certificate_sha256,
                    $public_key_sha256,
                    $private_key_secret_reference,
                    $not_before_ms,
                    $not_after_ms,
                    'Issued',
                    $created_at_ms
                );
                """;
            command.Parameters.AddWithValue(
                "$certificate_artifact_id",
                ToDatabaseGuid(certificateArtifact.Id.Value));
            command.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(certificateArtifact.OperationId.Value));
            command.Parameters.AddWithValue(
                "$certificate_sha256",
                certificateArtifact.CertificateSha256.Value);
            command.Parameters.AddWithValue(
                "$public_key_sha256",
                certificateArtifact.PublicKeySha256.Value);
            command.Parameters.AddWithValue(
                "$private_key_secret_reference",
                certificateArtifact.PrivateKeySecretReference);
            command.Parameters.AddWithValue(
                "$not_before_ms",
                ToUnixMilliseconds(certificateArtifact.NotBeforeUtc));
            command.Parameters.AddWithValue(
                "$not_after_ms",
                ToUnixMilliseconds(certificateArtifact.NotAfterUtc));
            command.Parameters.AddWithValue(
                "$created_at_ms",
                ToUnixMilliseconds(certificateArtifact.CreatedAtUtc));
            _ = command.ExecuteNonQuery();
        }

        var result = FindCertificateArtifactByOperation(
            connection,
            transaction,
            certificateArtifact.OperationId)
            ?? throw new InvalidOperationException(
                "The certificate artifact could not be read after creation.");
        transaction.Commit();
        return result;
    }

    public CertificateArtifact? FindCertificateArtifact(OperationId operationId)
    {
        EnsureInitialized();
        ValidateGuid(operationId.Value, nameof(operationId));
        using var connection = database.OpenConnection();
        return FindCertificateArtifactByOperation(connection, null, operationId);
    }

    public CertificateArtifact TransitionCertificateArtifactStatus(
        CertificateArtifactId certificateArtifactId,
        CertificateArtifactStatus expectedStatus,
        CertificateArtifactStatus newStatus)
    {
        EnsureInitialized();
        ValidateGuid(certificateArtifactId.Value, nameof(certificateArtifactId));
        if (!Enum.IsDefined(expectedStatus))
        {
            throw new ArgumentOutOfRangeException(nameof(expectedStatus));
        }

        if (!Enum.IsDefined(newStatus) ||
            !IsAllowedCertificateArtifactTransition(expectedStatus, newStatus))
        {
            throw new ArgumentOutOfRangeException(
                nameof(newStatus),
                newStatus,
                "The certificate artifact status transition is not allowed.");
        }

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindCertificateArtifactById(
            connection,
            transaction,
            certificateArtifactId)
            ?? throw new KeyNotFoundException("The certificate artifact does not exist.");
        if (existing.Status == newStatus)
        {
            transaction.Commit();
            return existing;
        }

        if (existing.Status != expectedStatus)
        {
            throw new ProductionCertificateArtifactStateConflictException();
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE certificate_artifacts
                SET status = $new_status
                WHERE certificate_artifact_id = $certificate_artifact_id
                  AND status = $expected_status;
                """;
            command.Parameters.AddWithValue("$new_status", newStatus.ToString());
            command.Parameters.AddWithValue(
                "$certificate_artifact_id",
                ToDatabaseGuid(certificateArtifactId.Value));
            command.Parameters.AddWithValue(
                "$expected_status",
                expectedStatus.ToString());
            if (command.ExecuteNonQuery() != 1)
            {
                throw new ProductionCertificateArtifactStateConflictException();
            }
        }

        var transitioned = FindCertificateArtifactById(
            connection,
            transaction,
            certificateArtifactId)
            ?? throw new InvalidOperationException(
                "The certificate artifact could not be read after its state transition.");
        transaction.Commit();
        return transitioned;
    }

    public RenewalOperation CompleteOwnedOperation(
        OperationId operationId,
        Guid executionEpoch,
        OperationStatus expectedStatus,
        OperationStatus terminalStatus,
        DateTimeOffset completedAtUtc,
        string? failureCode = null)
    {
        EnsureInitialized();
        ValidateGuid(operationId.Value, nameof(operationId));
        ValidateGuid(executionEpoch, nameof(executionEpoch));
        if (!IsOwnedActiveStatus(expectedStatus))
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedStatus),
                expectedStatus,
                "Owned completion requires an active expected status.");
        }

        if (!RenewalOperation.IsTerminal(terminalStatus))
        {
            throw new ArgumentOutOfRangeException(
                nameof(terminalStatus),
                terminalStatus,
                "An operation can be completed only with a terminal status.");
        }

        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindOperation(connection, transaction, operationId)
            ?? throw new KeyNotFoundException("The production operation does not exist.");
        if (RenewalOperation.IsTerminal(existing.Status))
        {
            if (existing.Status != terminalStatus ||
                existing.ExecutionEpoch != executionEpoch ||
                !string.Equals(existing.FailureCode, failureCode, StringComparison.Ordinal))
            {
                throw new ProductionOperationStateConflictException();
            }

            transaction.Commit();
            return existing;
        }

        if (existing.Status != expectedStatus ||
            existing.ExecutionEpoch != executionEpoch)
        {
            throw new ProductionOperationStateConflictException();
        }

        if (completedAtUtc.ToUniversalTime() < existing.UpdatedAtUtc)
        {
            throw new ArgumentException(
                "The completion timestamp cannot precede the persisted operation timestamp.",
                nameof(completedAtUtc));
        }

        _ = new RenewalOperation(
            existing.Id,
            existing.TargetId,
            existing.RequestKey,
            terminalStatus,
            existing.RequestedAtUtc,
            completedAtUtc,
            existing.StartedAtUtc,
            completedAtUtc,
            existing.ExecutionEpoch,
            failureCode);

        try
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE operations
                SET status = $status,
                    updated_at_ms = $completed_at_ms,
                    completed_at_ms = $completed_at_ms,
                    failure_code = $failure_code
                WHERE operation_id = $operation_id
                  AND status = $expected_status
                  AND execution_epoch = $execution_epoch;
                """;
            command.Parameters.AddWithValue("$status", terminalStatus.ToString());
            command.Parameters.AddWithValue(
                "$completed_at_ms",
                ToUnixMilliseconds(completedAtUtc));
            command.Parameters.AddWithValue(
                "$failure_code",
                failureCode ?? (object)DBNull.Value);
            command.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(operationId.Value));
            command.Parameters.AddWithValue(
                "$expected_status",
                expectedStatus.ToString());
            command.Parameters.AddWithValue(
                "$execution_epoch",
                ToDatabaseGuid(executionEpoch));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new ProductionOperationStateConflictException();
            }
        }
        catch (SqliteException exception)
            when (exception.SqliteErrorCode == 19 &&
                exception.Message.Contains(
                    "operation success requires",
                    StringComparison.Ordinal))
        {
            throw new ProductionOperationInvariantException(
                "A production operation cannot succeed before verification and cleanup evidence are durable.",
                exception);
        }

        var completed = FindOperation(connection, transaction, operationId)
            ?? throw new InvalidOperationException(
                "The production operation could not be read after completion.");
        transaction.Commit();
        return completed;
    }

    public RenewalOperation CompleteOwnedLiveRenewal(
        OperationId operationId,
        Guid executionEpoch,
        OperationStatus expectedStatus,
        OperationStatus terminalStatus,
        DateTimeOffset completedAtUtc,
        DateTimeOffset nextDueAtUtc,
        string? failureCode = null)
    {
        EnsureInitialized();
        ValidateGuid(operationId.Value, nameof(operationId));
        ValidateGuid(executionEpoch, nameof(executionEpoch));
        if (!IsOwnedActiveStatus(expectedStatus))
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedStatus),
                expectedStatus,
                "Owned completion requires an active expected status.");
        }

        if (!RenewalOperation.IsTerminal(terminalStatus))
        {
            throw new ArgumentOutOfRangeException(
                nameof(terminalStatus),
                terminalStatus,
                "A live renewal can be completed only with a terminal status.");
        }

        if (terminalStatus == OperationStatus.Succeeded && failureCode is not null)
        {
            throw new ArgumentException(
                "A successful live renewal cannot have a failure code.",
                nameof(failureCode));
        }

        var completedAt = completedAtUtc.ToUniversalTime();
        var nextDueAt = nextDueAtUtc.ToUniversalTime();
        using var connection = database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = FindOperation(connection, transaction, operationId)
            ?? throw new KeyNotFoundException("The production operation does not exist.");
        var policy = FindRenewalPolicyByTarget(
            connection,
            transaction,
            existing.TargetId)
            ?? throw new KeyNotFoundException(
                "The production operation target has no renewal policy.");

        if (RenewalOperation.IsTerminal(existing.Status))
        {
            ValidateIdempotentLiveCompletion(
                connection,
                transaction,
                existing,
                policy,
                executionEpoch,
                terminalStatus,
                completedAt,
                nextDueAt,
                failureCode);
            transaction.Commit();
            return existing;
        }

        if (existing.Status != expectedStatus ||
            existing.ExecutionEpoch != executionEpoch)
        {
            throw new ProductionOperationStateConflictException();
        }

        if (completedAt < existing.UpdatedAtUtc)
        {
            throw new ArgumentException(
                "The completion timestamp cannot precede the persisted operation timestamp.",
                nameof(completedAtUtc));
        }

        if (completedAt < policy.UpdatedAtUtc)
        {
            throw new ArgumentException(
                "The completion timestamp cannot precede the persisted renewal policy timestamp.",
                nameof(completedAtUtc));
        }

        _ = new RenewalOperation(
            existing.Id,
            existing.TargetId,
            existing.RequestKey,
            terminalStatus,
            existing.RequestedAtUtc,
            completedAt,
            existing.StartedAtUtc,
            completedAt,
            existing.ExecutionEpoch,
            failureCode);
        _ = new RenewalPolicy(
            policy.Id,
            policy.TargetId,
            policy.RenewBeforeDays,
            policy.CheckIntervalMinutes,
            policy.Enabled,
            nextDueAt,
            policy.CreatedAtUtc,
            completedAt);

        if (terminalStatus == OperationStatus.Succeeded)
        {
            RequireAggregateSuccessEvidence(connection, transaction, operationId);
            RequireLiveSuccessIntents(connection, transaction, operationId);
            var artifact = FindCertificateArtifactByOperation(
                connection,
                transaction,
                operationId)
                ?? throw new ProductionCertificateArtifactStateConflictException();
            if (artifact.Status != CertificateArtifactStatus.Issued)
            {
                throw new ProductionCertificateArtifactStateConflictException();
            }

            using var artifactCommand = connection.CreateCommand();
            artifactCommand.Transaction = transaction;
            artifactCommand.CommandText =
                """
                UPDATE certificate_artifacts
                SET status = 'Deployed'
                WHERE certificate_artifact_id = $certificate_artifact_id
                  AND operation_id = $operation_id
                  AND status = 'Issued';
                """;
            artifactCommand.Parameters.AddWithValue(
                "$certificate_artifact_id",
                ToDatabaseGuid(artifact.Id.Value));
            artifactCommand.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(operationId.Value));
            if (artifactCommand.ExecuteNonQuery() != 1)
            {
                throw new ProductionCertificateArtifactStateConflictException();
            }
        }

        using (var policyCommand = connection.CreateCommand())
        {
            policyCommand.Transaction = transaction;
            policyCommand.CommandText =
                """
                UPDATE renewal_policies
                SET next_due_at_ms = $next_due_at_ms,
                    updated_at_ms = $completed_at_ms
                WHERE renewal_policy_id = $renewal_policy_id
                  AND target_id = $target_id
                  AND updated_at_ms = $expected_updated_at_ms;
                """;
            policyCommand.Parameters.AddWithValue(
                "$next_due_at_ms",
                ToUnixMilliseconds(nextDueAt));
            policyCommand.Parameters.AddWithValue(
                "$completed_at_ms",
                ToUnixMilliseconds(completedAt));
            policyCommand.Parameters.AddWithValue(
                "$renewal_policy_id",
                ToDatabaseGuid(policy.Id.Value));
            policyCommand.Parameters.AddWithValue(
                "$target_id",
                ToDatabaseGuid(existing.TargetId.Value));
            policyCommand.Parameters.AddWithValue(
                "$expected_updated_at_ms",
                ToUnixMilliseconds(policy.UpdatedAtUtc));
            if (policyCommand.ExecuteNonQuery() != 1)
            {
                throw new ProductionOperationStateConflictException();
            }
        }

        try
        {
            using var operationCommand = connection.CreateCommand();
            operationCommand.Transaction = transaction;
            operationCommand.CommandText =
                """
                UPDATE operations
                SET status = $status,
                    updated_at_ms = $completed_at_ms,
                    completed_at_ms = $completed_at_ms,
                    failure_code = $failure_code
                WHERE operation_id = $operation_id
                  AND status = $expected_status
                  AND execution_epoch = $execution_epoch;
                """;
            operationCommand.Parameters.AddWithValue(
                "$status",
                terminalStatus.ToString());
            operationCommand.Parameters.AddWithValue(
                "$completed_at_ms",
                ToUnixMilliseconds(completedAt));
            operationCommand.Parameters.AddWithValue(
                "$failure_code",
                failureCode ?? (object)DBNull.Value);
            operationCommand.Parameters.AddWithValue(
                "$operation_id",
                ToDatabaseGuid(operationId.Value));
            operationCommand.Parameters.AddWithValue(
                "$expected_status",
                expectedStatus.ToString());
            operationCommand.Parameters.AddWithValue(
                "$execution_epoch",
                ToDatabaseGuid(executionEpoch));
            if (operationCommand.ExecuteNonQuery() != 1)
            {
                throw new ProductionOperationStateConflictException();
            }
        }
        catch (SqliteException exception)
            when (exception.SqliteErrorCode == 19 &&
                exception.Message.Contains(
                    "operation success requires",
                    StringComparison.Ordinal))
        {
            throw new ProductionOperationInvariantException(
                "A successful live renewal requires aggregate all-name TLS verification and challenge cleanup evidence.",
                exception);
        }

        var completed = FindOperation(connection, transaction, operationId)
            ?? throw new InvalidOperationException(
                "The production operation could not be read after live completion.");
        transaction.Commit();
        return completed;
    }

    public RenewalOperation? FindOperation(OperationId operationId)
    {
        EnsureInitialized();
        ValidateGuid(operationId.Value, nameof(operationId));
        using var connection = database.OpenConnection();
        return FindOperation(connection, null, operationId);
    }

    public IReadOnlyList<RenewalOperation> ListActiveOperations(int maximumCount)
    {
        EnsureInitialized();
        if (maximumCount is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumCount),
                maximumCount,
                "An active-operation page must contain between 1 and 500 records.");
        }

        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT {OperationProjectionColumns}
            FROM operations
            WHERE status IN ('Queued', 'Running', 'Blocked', 'RollbackRequired')
            ORDER BY requested_at_ms, operation_id
            LIMIT $maximum_count;
            """;
        command.Parameters.AddWithValue("$maximum_count", maximumCount);
        using var reader = command.ExecuteReader();
        var operations = new List<RenewalOperation>(maximumCount);
        while (reader.Read())
        {
            operations.Add(ReadOperation(reader));
        }

        return operations.AsReadOnly();
    }

    public IReadOnlyList<OperationEvidence> ReadOperationEvidence(OperationId operationId)
    {
        EnsureInitialized();
        ValidateGuid(operationId.Value, nameof(operationId));
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT
                operation_id,
                sequence,
                kind,
                stage,
                outcome,
                recorded_at_ms,
                code,
                description
            FROM operation_evidence
            WHERE operation_id = $operation_id
            ORDER BY sequence;
            """;
        command.Parameters.AddWithValue("$operation_id", ToDatabaseGuid(operationId.Value));
        using var reader = command.ExecuteReader();
        var evidence = new List<OperationEvidence>();
        while (reader.Read())
        {
            evidence.Add(ReadEvidence(reader));
        }

        return evidence.AsReadOnly();
    }

    private static RenewalOperation? FindOperation(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        OperationId operationId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"""
            SELECT {OperationProjectionColumns}
            FROM operations
            WHERE operation_id = $operation_id;
            """;
        command.Parameters.AddWithValue("$operation_id", ToDatabaseGuid(operationId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadOperation(reader) : null;
    }

    private static RenewalPolicy? FindRenewalPolicyByTarget(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        TargetId targetId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"""
            SELECT {RenewalPolicyProjectionColumns}
            FROM renewal_policies
            WHERE target_id = $target_id;
            """;
        command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(targetId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadRenewalPolicy(reader) : null;
    }

    private static void ValidateIdempotentLiveCompletion(
        SqliteConnection connection,
        SqliteTransaction transaction,
        RenewalOperation operation,
        RenewalPolicy policy,
        Guid executionEpoch,
        OperationStatus terminalStatus,
        DateTimeOffset completedAtUtc,
        DateTimeOffset nextDueAtUtc,
        string? failureCode)
    {
        if (operation.Status != terminalStatus ||
            operation.ExecutionEpoch != executionEpoch ||
            ToUnixMilliseconds(operation.CompletedAtUtc!.Value) !=
                ToUnixMilliseconds(completedAtUtc) ||
            !string.Equals(operation.FailureCode, failureCode, StringComparison.Ordinal) ||
            !policy.NextDueAtUtc.HasValue ||
            ToUnixMilliseconds(policy.NextDueAtUtc.Value) !=
                ToUnixMilliseconds(nextDueAtUtc) ||
            ToUnixMilliseconds(policy.UpdatedAtUtc) !=
                ToUnixMilliseconds(completedAtUtc))
        {
            throw new ProductionOperationStateConflictException();
        }

        if (terminalStatus != OperationStatus.Succeeded)
        {
            return;
        }

        RequireAggregateSuccessEvidence(connection, transaction, operation.Id);
        RequireLiveSuccessIntents(connection, transaction, operation.Id);
        var artifact = FindCertificateArtifactByOperation(
            connection,
            transaction,
            operation.Id);
        if (artifact?.Status != CertificateArtifactStatus.Deployed)
        {
            throw new ProductionCertificateArtifactStateConflictException();
        }
    }

    private static void RequireAggregateSuccessEvidence(
        SqliteConnection connection,
        SqliteTransaction transaction,
        OperationId operationId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT
                EXISTS (
                    SELECT 1
                    FROM operation_evidence
                    WHERE operation_id = $operation_id
                      AND kind = 'Verification'
                      AND outcome = 'Succeeded'
                      AND code = 'tls.all_names_verified'
                )
                AND EXISTS (
                    SELECT 1
                    FROM operation_evidence
                    WHERE operation_id = $operation_id
                      AND kind = 'Cleanup'
                      AND outcome = 'Succeeded'
                      AND code = 'challenge.cleanup_complete'
                );
            """;
        command.Parameters.AddWithValue(
            "$operation_id",
            ToDatabaseGuid(operationId.Value));
        if (Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 1)
        {
            throw new ProductionOperationInvariantException(
                "A successful live renewal requires aggregate all-name TLS verification and challenge cleanup evidence.");
        }
    }

    private static void RequireLiveSuccessIntents(
        SqliteConnection connection,
        SqliteTransaction transaction,
        OperationId operationId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT
                EXISTS (
                    SELECT 1
                    FROM operation_intents
                    WHERE operation_id = $operation_id
                      AND kind = 'Commit'
                      AND status IN ('Applied', 'Reconciled')
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM operation_intents
                    WHERE operation_id = $operation_id
                      AND kind = 'ChallengeWrite'
                      AND status <> 'Reconciled'
                );
            """;
        command.Parameters.AddWithValue(
            "$operation_id",
            ToDatabaseGuid(operationId.Value));
        if (Convert.ToInt64(
                command.ExecuteScalar(),
                CultureInfo.InvariantCulture) != 1)
        {
            throw new ProductionOperationInvariantException(
                "A successful live renewal requires an applied commit intent and reconciliation of every challenge-write intent.");
        }
    }

    private static RenewalOperation? FindOperationByRequestKey(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string requestKey)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"""
            SELECT {OperationProjectionColumns}
            FROM operations
            WHERE request_key = $request_key;
            """;
        command.Parameters.AddWithValue("$request_key", requestKey);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadOperation(reader) : null;
    }

    private static AuditEvent? FindAuditEvent(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        AuditEventId auditEventId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"""
            SELECT {AuditEventProjectionColumns}
            FROM audit_events
            WHERE audit_event_id = $audit_event_id;
            """;
        command.Parameters.AddWithValue(
            "$audit_event_id",
            ToDatabaseGuid(auditEventId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadAuditEvent(reader) : null;
    }

    private static OperationIntent? FindOperationIntentByKey(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string idempotencyKey)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT
                operation_intent_id,
                operation_id,
                sequence,
                kind,
                idempotency_key,
                status,
                recorded_at_ms,
                applied_at_ms,
                remote_path
            FROM operation_intents
            WHERE idempotency_key = $idempotency_key;
            """;
        command.Parameters.AddWithValue("$idempotency_key", idempotencyKey);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadOperationIntent(reader) : null;
    }

    private static OperationIntent? FindOperationIntentById(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        OperationIntentId operationIntentId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT
                operation_intent_id,
                operation_id,
                sequence,
                kind,
                idempotency_key,
                status,
                recorded_at_ms,
                applied_at_ms,
                remote_path
            FROM operation_intents
            WHERE operation_intent_id = $operation_intent_id;
            """;
        command.Parameters.AddWithValue(
            "$operation_intent_id",
            ToDatabaseGuid(operationIntentId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadOperationIntent(reader) : null;
    }

    private static AcmeAccountRecord? FindAcmeAccount(
        SqliteConnection connection,
        SqliteTransaction transaction,
        AcmeAccountId accountId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT
                acme_account_id,
                directory_uri,
                account_uri,
                contact_email,
                key_secret_reference,
                status,
                created_at_ms,
                updated_at_ms
            FROM acme_accounts
            WHERE acme_account_id = $acme_account_id;
            """;
        command.Parameters.AddWithValue(
            "$acme_account_id",
            ToDatabaseGuid(accountId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadAcmeAccount(reader) : null;
    }

    private static AcmeAccountRecord? FindAcmeAccountByDirectoryAndSecretReference(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string directoryUri,
        string keySecretReference)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT
                acme_account_id,
                directory_uri,
                account_uri,
                contact_email,
                key_secret_reference,
                status,
                created_at_ms,
                updated_at_ms
            FROM acme_accounts
            WHERE directory_uri = $directory_uri
              AND key_secret_reference = $key_secret_reference;
            """;
        command.Parameters.AddWithValue("$directory_uri", directoryUri);
        command.Parameters.AddWithValue("$key_secret_reference", keySecretReference);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadAcmeAccount(reader) : null;
    }

    private static CertificateArtifact? FindCertificateArtifactByOperation(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        OperationId operationId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT
                certificate_artifact_id,
                operation_id,
                certificate_sha256,
                public_key_sha256,
                private_key_secret_reference,
                not_before_ms,
                not_after_ms,
                status,
                created_at_ms
            FROM certificate_artifacts
            WHERE operation_id = $operation_id;
            """;
        command.Parameters.AddWithValue(
            "$operation_id",
            ToDatabaseGuid(operationId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadCertificateArtifact(reader) : null;
    }

    private static CertificateArtifact? FindCertificateArtifactById(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CertificateArtifactId certificateArtifactId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT
                certificate_artifact_id,
                operation_id,
                certificate_sha256,
                public_key_sha256,
                private_key_secret_reference,
                not_before_ms,
                not_after_ms,
                status,
                created_at_ms
            FROM certificate_artifacts
            WHERE certificate_artifact_id = $certificate_artifact_id;
            """;
        command.Parameters.AddWithValue(
            "$certificate_artifact_id",
            ToDatabaseGuid(certificateArtifactId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadCertificateArtifact(reader) : null;
    }

    private static (string TargetId, string IdentitySha256)? ReadEnrollmentIdentity(
        SqliteConnection connection,
        SqliteTransaction transaction,
        EnrollmentId enrollmentId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT target_id, identity_sha256
            FROM enrollments
            WHERE enrollment_id = $enrollment_id;
            """;
        command.Parameters.AddWithValue(
            "$enrollment_id",
            ToDatabaseGuid(enrollmentId.Value));
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? (reader.GetString(0), reader.GetString(1))
            : null;
    }

    private static bool PersistedConnectionIdentityMatches(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ConnectionProfile connectionProfile)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT
                host,
                port,
                username,
                credential_reference,
                host_key_algorithm,
                host_key_fingerprint,
                raw_host_key
            FROM connections
            WHERE connection_id = $connection_id;
            """;
        command.Parameters.AddWithValue(
            "$connection_id",
            ToDatabaseGuid(connectionProfile.Id.Value));
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return true;
        }

        var persistedAlgorithm = reader.IsDBNull(4) ? null : reader.GetString(4);
        var persistedRawHostKey = reader.IsDBNull(6)
            ? null
            : reader.GetFieldValue<byte[]>(6);
        var proposedRawHostKey = connectionProfile.ExportRawHostKey();
        return string.Equals(
                reader.GetString(0),
                connectionProfile.Endpoint.Host,
                StringComparison.Ordinal) &&
            reader.GetInt32(1) == connectionProfile.Endpoint.Port &&
            string.Equals(
                reader.GetString(2),
                connectionProfile.Username,
                StringComparison.Ordinal) &&
            string.Equals(
                reader.GetString(3),
                connectionProfile.CredentialReference,
                StringComparison.Ordinal) &&
            string.Equals(
                persistedAlgorithm,
                connectionProfile.HostKeyAlgorithm,
                StringComparison.Ordinal) &&
            string.Equals(
                reader.GetString(5),
                connectionProfile.HostKeyFingerprint,
                StringComparison.Ordinal) &&
            ByteArraysEqual(persistedRawHostKey, proposedRawHostKey);
    }

    private static string ComputeEnrollmentIdentity(TargetEnrollment enrollment)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendIdentityValue(hash, ToDatabaseGuid(enrollment.Connection.Id.Value));
        AppendIdentityValue(hash, enrollment.Connection.Endpoint.Host);
        AppendIdentityValue(
            hash,
            enrollment.Connection.Endpoint.Port.ToString(CultureInfo.InvariantCulture));
        AppendIdentityValue(hash, enrollment.Connection.Username);
        AppendIdentityValue(hash, enrollment.Connection.CredentialReference);
        AppendIdentityValue(hash, enrollment.Connection.HostKeyAlgorithm);
        AppendIdentityValue(hash, enrollment.Connection.HostKeyFingerprint);
        AppendIdentityValue(
            hash,
            enrollment.Connection.ExportRawHostKey() is { } rawHostKey
                ? Convert.ToBase64String(rawHostKey)
                : null);
        AppendIdentityValue(hash, ToDatabaseGuid(enrollment.Target.Id.Value));
        AppendIdentityValue(hash, ToDatabaseGuid(enrollment.Target.ConnectionId.Value));
        AppendIdentityValue(hash, enrollment.Target.PrimaryName.Value);
        foreach (var name in enrollment.Target.Names
                     .Select(static item => item.Value)
                     .Order(StringComparer.Ordinal))
        {
            AppendIdentityValue(hash, name);
        }

        AppendIdentityValue(
            hash,
            ToDatabaseGuid(enrollment.DeploymentPlan.Id.Value));
        AppendIdentityValue(
            hash,
            ToDatabaseGuid(enrollment.DeploymentPlan.TargetId.Value));
        AppendIdentityValue(hash, enrollment.DeploymentPlan.Kind.ToString());
        AppendIdentityValue(hash, enrollment.DeploymentPlan.ChallengeWebroot.Value);
        AppendIdentityValue(
            hash,
            enrollment.DeploymentPlan.RemoteIncomingRoot?.Value);
        AppendIdentityValue(hash, enrollment.DeploymentPlan.CertificatePath.Value);
        AppendIdentityValue(hash, enrollment.DeploymentPlan.PrivateKeyPath.Value);
        AppendIdentityValue(hash, ToDatabaseGuid(enrollment.RenewalPolicy.Id.Value));
        AppendIdentityValue(
            hash,
            ToDatabaseGuid(enrollment.RenewalPolicy.TargetId.Value));
        AppendIdentityValue(
            hash,
            ToDatabaseGuid(enrollment.IssuanceProfile.TargetId.Value));
        AppendIdentityValue(hash, enrollment.IssuanceProfile.DirectoryUri.AbsoluteUri);
        AppendIdentityValue(
            hash,
            enrollment.IssuanceProfile.AccountKeySecretReference);
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void AppendIdentityValue(IncrementalHash hash, string? value)
    {
        var bytes = value is null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }

    private static bool ByteArraysEqual(byte[]? left, byte[]? right)
    {
        if (left is null || right is null)
        {
            return left is null && right is null;
        }

        return CryptographicOperations.FixedTimeEquals(left, right);
    }

    private static void EnsureNoActiveOperation(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TargetId targetId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT 1
            FROM operations
            WHERE target_id = $target_id
              AND status IN ('Queued', 'Running', 'Blocked', 'RollbackRequired')
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$target_id", ToDatabaseGuid(targetId.Value));
        if (command.ExecuteScalar() is not null)
        {
            throw new ProductionOperationAlreadyActiveException();
        }
    }

    private static RenewalOperation ReadOperation(SqliteDataReader reader) =>
        new(
            new OperationId(ReadDatabaseGuid(reader.GetString(0))),
            new TargetId(ReadDatabaseGuid(reader.GetString(1))),
            reader.GetString(2),
            ParseEnum<OperationStatus>(reader.GetString(3), "operation status"),
            FromUnixMilliseconds(reader.GetInt64(4)),
            FromUnixMilliseconds(reader.GetInt64(5)),
            reader.IsDBNull(6) ? null : FromUnixMilliseconds(reader.GetInt64(6)),
            reader.IsDBNull(7) ? null : FromUnixMilliseconds(reader.GetInt64(7)),
            reader.IsDBNull(8) ? null : ReadDatabaseGuid(reader.GetString(8)),
            reader.IsDBNull(9) ? null : reader.GetString(9));

    private static ConnectionProfile ReadConnection(SqliteDataReader reader) =>
        new(
            new ConnectionId(ReadDatabaseGuid(reader.GetString(0))),
            reader.GetString(1),
            new ConnectionEndpoint(reader.GetString(2), reader.GetInt32(3)),
            reader.GetString(4),
            reader.GetString(5),
            reader.IsDBNull(6) ? null : reader.GetString(6),
            reader.GetString(7),
            FromUnixMilliseconds(reader.GetInt64(9)),
            FromUnixMilliseconds(reader.GetInt64(10)),
            ReadDatabaseBoolean(reader.GetInt64(11)),
            reader.IsDBNull(8) ? default : reader.GetFieldValue<byte[]>(8));

    private static DeploymentPlan ReadDeploymentPlan(SqliteDataReader reader) =>
        new(
            new DeploymentPlanId(ReadDatabaseGuid(reader.GetString(0))),
            new TargetId(ReadDatabaseGuid(reader.GetString(1))),
            ParseEnum<DeploymentKind>(reader.GetString(2), "deployment kind"),
            new RemotePath(reader.GetString(3)),
            reader.IsDBNull(4) ? null : new RemotePath(reader.GetString(4)),
            new RemotePath(reader.GetString(5)),
            new RemotePath(reader.GetString(6)),
            FromUnixMilliseconds(reader.GetInt64(7)),
            FromUnixMilliseconds(reader.GetInt64(8)),
            ReadDatabaseBoolean(reader.GetInt64(9)));

    private static RenewalPolicy ReadRenewalPolicy(SqliteDataReader reader) =>
        new(
            new RenewalPolicyId(ReadDatabaseGuid(reader.GetString(0))),
            new TargetId(ReadDatabaseGuid(reader.GetString(1))),
            reader.GetInt32(2),
            reader.GetInt32(3),
            ReadDatabaseBoolean(reader.GetInt64(4)),
            reader.IsDBNull(5) ? null : FromUnixMilliseconds(reader.GetInt64(5)),
            FromUnixMilliseconds(reader.GetInt64(6)),
            FromUnixMilliseconds(reader.GetInt64(7)));

    private static TargetIssuanceProfile ReadTargetIssuanceProfile(
        SqliteDataReader reader) =>
        new(
            new TargetId(ReadDatabaseGuid(reader.GetString(0))),
            new Uri(reader.GetString(1), UriKind.Absolute),
            new AcmeContactUri(reader.GetString(2)),
            ReadDatabaseBoolean(reader.GetInt64(3)),
            reader.IsDBNull(4) ? null : FromUnixMilliseconds(reader.GetInt64(4)),
            reader.GetString(5),
            reader.IsDBNull(6) ? null : new Uri(reader.GetString(6), UriKind.Absolute),
            FromUnixMilliseconds(reader.GetInt64(7)),
            FromUnixMilliseconds(reader.GetInt64(8)));

    private static AcmeAccountRecord ReadAcmeAccount(SqliteDataReader reader) =>
        new(
            new AcmeAccountId(ReadDatabaseGuid(reader.GetString(0))),
            new Uri(reader.GetString(1), UriKind.Absolute),
            reader.IsDBNull(2) ? null : new Uri(reader.GetString(2), UriKind.Absolute),
            reader.IsDBNull(3) ? null : reader.GetString(3),
            reader.GetString(4),
            ParseEnum<AcmeAccountStatus>(reader.GetString(5), "ACME account status"),
            FromUnixMilliseconds(reader.GetInt64(6)),
            FromUnixMilliseconds(reader.GetInt64(7)));

    private static CertificateArtifact ReadCertificateArtifact(
        SqliteDataReader reader) =>
        new(
            new CertificateArtifactId(ReadDatabaseGuid(reader.GetString(0))),
            new OperationId(ReadDatabaseGuid(reader.GetString(1))),
            new Sha256Digest(reader.GetString(2)),
            new Sha256Digest(reader.GetString(3)),
            reader.GetString(4),
            FromUnixMilliseconds(reader.GetInt64(5)),
            FromUnixMilliseconds(reader.GetInt64(6)),
            ParseEnum<CertificateArtifactStatus>(
                reader.GetString(7),
                "certificate artifact status"),
            FromUnixMilliseconds(reader.GetInt64(8)));

    private static OperationEvidence ReadEvidence(SqliteDataReader reader) =>
        new(
            new OperationId(ReadDatabaseGuid(reader.GetString(0))),
            reader.GetInt64(1),
            ParseEnum<OperationEvidenceKind>(reader.GetString(2), "evidence kind"),
            reader.IsDBNull(3) ? null : reader.GetString(3),
            ParseEnum<OperationEvidenceOutcome>(reader.GetString(4), "evidence outcome"),
            FromUnixMilliseconds(reader.GetInt64(5)),
            reader.GetString(6),
            reader.GetString(7));

    private static AuditEvent ReadAuditEvent(SqliteDataReader reader) =>
        new(
            new AuditEventId(ReadDatabaseGuid(reader.GetString(0))),
            reader.GetInt64(1),
            reader.IsDBNull(2)
                ? null
                : new OperationId(ReadDatabaseGuid(reader.GetString(2))),
            reader.IsDBNull(3)
                ? null
                : new TargetId(ReadDatabaseGuid(reader.GetString(3))),
            reader.GetString(4),
            reader.GetString(5),
            FromUnixMilliseconds(reader.GetInt64(6)),
            reader.GetString(7),
            reader.GetString(8));

    private static OperationIntent ReadOperationIntent(SqliteDataReader reader) =>
        new(
            new OperationIntentId(ReadDatabaseGuid(reader.GetString(0))),
            new OperationId(ReadDatabaseGuid(reader.GetString(1))),
            reader.GetInt64(2),
            ParseEnum<OperationIntentKind>(reader.GetString(3), "intent kind"),
            reader.GetString(4),
            ParseEnum<OperationIntentStatus>(reader.GetString(5), "intent status"),
            FromUnixMilliseconds(reader.GetInt64(6)),
            reader.IsDBNull(7) ? null : FromUnixMilliseconds(reader.GetInt64(7)),
            reader.IsDBNull(8) ? null : reader.GetString(8));

    private static TEnum ParseEnum<TEnum>(string value, string fieldName)
        where TEnum : struct, Enum
    {
        if (!Enum.TryParse<TEnum>(value, ignoreCase: false, out var result) ||
            !Enum.IsDefined(result))
        {
            throw new InvalidOperationException($"The persisted {fieldName} is invalid.");
        }

        return result;
    }

    private static bool IsOwnedActiveStatus(OperationStatus status) =>
        status is OperationStatus.Running or
            OperationStatus.Blocked or
            OperationStatus.RollbackRequired;

    private static bool IsAllowedIntentTransition(
        OperationIntentStatus expectedStatus,
        OperationIntentStatus newStatus) =>
        expectedStatus == newStatus ||
        (expectedStatus == OperationIntentStatus.Planned &&
            newStatus is OperationIntentStatus.Applied or
                OperationIntentStatus.Reconciled or
                OperationIntentStatus.Failed or
                OperationIntentStatus.Uncertain) ||
        (expectedStatus == OperationIntentStatus.Applied &&
            newStatus is OperationIntentStatus.Reconciled or
                OperationIntentStatus.Failed) ||
        (expectedStatus == OperationIntentStatus.Uncertain &&
            newStatus is OperationIntentStatus.Applied or
                OperationIntentStatus.Reconciled or
                OperationIntentStatus.Failed) ||
        (expectedStatus == OperationIntentStatus.Failed &&
            newStatus is OperationIntentStatus.Applied or
                OperationIntentStatus.Reconciled);

    private static bool IsAllowedCertificateArtifactTransition(
        CertificateArtifactStatus expectedStatus,
        CertificateArtifactStatus newStatus) =>
        expectedStatus == newStatus ||
        (expectedStatus == CertificateArtifactStatus.Issued &&
            newStatus is CertificateArtifactStatus.Deployed or
                CertificateArtifactStatus.Revoked) ||
        (expectedStatus == CertificateArtifactStatus.Deployed &&
            newStatus == CertificateArtifactStatus.Revoked);

    private static bool AuditEventMatches(AuditEvent existing, AuditEvent proposed) =>
        existing.Id == proposed.Id &&
        existing.OperationId == proposed.OperationId &&
        existing.TargetId == proposed.TargetId &&
        string.Equals(existing.ActorSid, proposed.ActorSid, StringComparison.Ordinal) &&
        string.Equals(existing.EventType, proposed.EventType, StringComparison.Ordinal) &&
        ToUnixMilliseconds(existing.OccurredAtUtc) ==
            ToUnixMilliseconds(proposed.OccurredAtUtc) &&
        string.Equals(existing.Code, proposed.Code, StringComparison.Ordinal) &&
        string.Equals(existing.Description, proposed.Description, StringComparison.Ordinal);

    private static bool ReadDatabaseBoolean(long value) => value switch
    {
        0 => false,
        1 => true,
        _ => throw new InvalidOperationException(
            "A persisted Boolean value is invalid."),
    };

    private static string NormalizeHttpsUri(Uri uri, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(uri, parameterName);
        if (!uri.IsAbsoluteUri ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            uri.AbsoluteUri.Length > 2_048 ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException(
                "An ACME URI must be absolute HTTPS without user information or a fragment.",
                parameterName);
        }

        return uri.AbsoluteUri;
    }

    private static void ValidateIdempotencyKey(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 200 ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException(
                "The idempotency key is invalid.",
                nameof(value));
        }
    }

    private static void ValidateSecretReference(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > 200 ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException(
                "The secret reference is invalid.",
                parameterName);
        }
    }

    private static void ValidateGuid(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "An identifier cannot be empty.",
                parameterName);
        }
    }

    private static int ToDatabaseBoolean(bool value) => value ? 1 : 0;

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
                "The SQLite production store has not been initialized.");
        }
    }
}
