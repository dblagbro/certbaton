using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using CertBaton.Application.Persistence;
using CertBaton.Domain.Connections;
using CertBaton.Domain.Deployments;
using CertBaton.Domain.Operations;
using CertBaton.Domain.Scheduling;
using CertBaton.Domain.Targets;
using CertBaton.Persistence.Sqlite;
using Microsoft.Data.Sqlite;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class ProductionSqlitePersistenceTests
{
    private static readonly DateTimeOffset testStart =
        new(2026, 7, 31, 13, 0, 0, TimeSpan.Zero);
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
    public void InitializationCreatesStrictV5SchemaAndIsIdempotent()
    {
        var (store, databasePath) = CreateStore();
        store.Initialize(testStart.AddMinutes(1));
        var reopened = new SqliteProductionStore(databasePath);
        reopened.Initialize(testStart.AddMinutes(2));

        using var connection = OpenReadOnly(databasePath);
        Assert.AreEqual(
            SqliteProductionStore.ApplicationId,
            ReadInt64(connection, "PRAGMA application_id;"));
        Assert.AreEqual(
            SqliteProductionStore.CurrentSchemaVersion,
            ReadInt64(connection, "PRAGMA user_version;"));
        Assert.AreEqual(5L, ReadInt64(connection, "SELECT COUNT(*) FROM schema_migrations;"));
        Assert.AreEqual(
            18L,
            ReadInt64(
                connection,
                """
                SELECT COUNT(*)
                FROM pragma_table_list
                WHERE schema = 'main'
                  AND name IN (
                    'schema_migrations', 'jobs', 'evidence', 'connections',
                    'targets', 'target_names', 'deployment_plans', 'operations',
                    'operation_evidence', 'operation_intents', 'acme_accounts',
                    'acme_orders', 'certificate_artifacts', 'renewal_policies',
                    'tls_probe_evidence', 'audit_events', 'target_issuance_profiles',
                    'enrollments'
                  )
                  AND strict = 1;
                """));
    }

    [TestMethod]
    public void V1SimulatorDataSurvivesForwardMigration()
    {
        var directory = CreateTestDirectory();
        var databasePath = Path.Combine(directory, "state.db");
        var simulator = new SqliteSimulationJobStore(databasePath);
        simulator.Initialize(testStart);
        var jobId = Guid.Parse("84731d40-5853-4bbc-a618-20c009083da7");
        _ = simulator.CreateOrGetJob(jobId, "preserved-v1-job", null, testStart);
        DowngradeFixtureToV1(databasePath);

        var production = new SqliteProductionStore(databasePath);
        production.Initialize(testStart.AddMinutes(1));

        using var connection = OpenReadOnly(databasePath);
        Assert.AreEqual(5L, ReadInt64(connection, "PRAGMA user_version;"));
        Assert.AreEqual(
            jobId.ToString("D", CultureInfo.InvariantCulture),
            Convert.ToString(
                ReadScalar(
                    connection,
                    "SELECT job_id FROM jobs WHERE request_key = 'preserved-v1-job';"),
                CultureInfo.InvariantCulture));
        Assert.AreEqual(5L, ReadInt64(connection, "SELECT COUNT(*) FROM schema_migrations;"));
    }

    [TestMethod]
    public void V3IntentDataSurvivesV5MigrationAndAcceptsRemoteHelperPhases()
    {
        var (store, databasePath) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                fixture.Target.Id,
                "preserved-v3-operation",
                testStart));
        var preserved = store.CreateOrGetOperationIntent(
            new OperationIntent(
                OperationIntentId.Create(),
                operation.Id,
                sequence: 1,
                OperationIntentKind.CertificateDeploy,
                "preserved-v3-intent",
                OperationIntentStatus.Planned,
                testStart));
        DowngradeFixtureToV3(databasePath);

        var reopened = new SqliteProductionStore(databasePath);
        reopened.Initialize(testStart.AddMinutes(1));

        Assert.AreEqual(preserved, reopened.FindOperationIntent(preserved.Id));
        var remotePrepare = reopened.CreateOrGetOperationIntent(
            new OperationIntent(
                OperationIntentId.Create(),
                operation.Id,
                sequence: 2,
                OperationIntentKind.RemotePrepare,
                "v4-remote-prepare",
                OperationIntentStatus.Planned,
                testStart.AddMinutes(2)));
        Assert.AreEqual(OperationIntentKind.RemotePrepare, remotePrepare.Kind);
        using var connection = OpenReadOnly(databasePath);
        Assert.AreEqual(5L, ReadInt64(connection, "PRAGMA user_version;"));
        Assert.AreEqual(5L, ReadInt64(connection, "SELECT COUNT(*) FROM schema_migrations;"));
    }

    [TestMethod]
    public void V4PathlessChallengeIntentSurvivesV5MigrationWithoutChangingPriorChecksums()
    {
        var (store, databasePath) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                fixture.Target.Id,
                "preserved-v4-challenge",
                testStart));
        var preserved = store.CreateOrGetOperationIntent(
            new OperationIntent(
                OperationIntentId.Create(),
                operation.Id,
                sequence: 1,
                OperationIntentKind.ChallengeWrite,
                "preserved-v4-challenge-intent",
                OperationIntentStatus.Planned,
                testStart,
                remotePath: "/srv/www/.well-known/acme-challenge/token"));
        var priorMigrations = ReadMigrationMetadata(databasePath, 4);
        DowngradeFixtureToV4(databasePath);

        var reopened = new SqliteProductionStore(databasePath);
        reopened.Initialize(testStart.AddMinutes(1));

        var migrated = reopened.FindOperationIntent(preserved.Id);
        Assert.IsNotNull(migrated);
        Assert.AreEqual(preserved.Id, migrated.Id);
        Assert.AreEqual(preserved.OperationId, migrated.OperationId);
        Assert.AreEqual(preserved.Sequence, migrated.Sequence);
        Assert.AreEqual(preserved.Kind, migrated.Kind);
        Assert.AreEqual(preserved.IdempotencyKey, migrated.IdempotencyKey);
        Assert.AreEqual(preserved.Status, migrated.Status);
        Assert.IsNull(migrated.RemotePath);
        CollectionAssert.AreEqual(
            priorMigrations,
            ReadMigrationMetadata(databasePath, 4));
        using var connection = OpenReadOnly(databasePath);
        Assert.AreEqual(5L, ReadInt64(connection, "PRAGMA user_version;"));
        Assert.AreEqual(5L, ReadInt64(connection, "SELECT COUNT(*) FROM schema_migrations;"));
    }

    [TestMethod]
    public void TamperedV4ChecksumBlocksV5MigrationBeforeAnySchemaMutation()
    {
        var (_, databasePath) = CreateStore();
        DowngradeFixtureToV4(databasePath);
        using (var connection = OpenReadWrite(databasePath))
        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                "UPDATE schema_migrations SET checksum_sha256 = $checksum WHERE version = 4;";
            command.Parameters.AddWithValue("$checksum", new string('0', 64));
            Assert.AreEqual(1, command.ExecuteNonQuery());
        }

        var reopened = new SqliteProductionStore(databasePath);
        Assert.ThrowsExactly<InvalidOperationException>(
            () => reopened.Initialize(testStart.AddMinutes(1)));

        using var verification = OpenReadOnly(databasePath);
        Assert.AreEqual(4L, ReadInt64(verification, "PRAGMA user_version;"));
        Assert.AreEqual(4L, ReadInt64(
            verification,
            "SELECT COUNT(*) FROM schema_migrations;"));
        Assert.AreEqual(
            0L,
            ReadInt64(
                verification,
                "SELECT COUNT(*) FROM pragma_table_info('operation_intents') WHERE name = 'remote_path';"));
    }

    [TestMethod]
    public void ConfigurationUpsertsAreIdempotentAndRetainOnePrimaryName()
    {
        var (store, databasePath) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        store.SaveConnection(fixture.Connection);
        store.SaveTarget(fixture.Target);

        var deploymentPlan = new DeploymentPlan(
            new DeploymentPlanId(Guid.Parse("4108b808-2af8-48cb-85e9-e9e9c9539b91")),
            fixture.Target.Id,
            DeploymentKind.Nginx,
            new RemotePath("/srv/www/site"),
            new RemotePath("/var/lib/certbaton/incoming/site"),
            new RemotePath("/etc/nginx/tls/site.fullchain.pem"),
            new RemotePath("/etc/nginx/tls/site.key"),
            testStart,
            testStart);
        var renewalPolicy = new RenewalPolicy(
            new RenewalPolicyId(Guid.Parse("705a67b8-b6b3-4c37-945d-7a77f11bdca1")),
            fixture.Target.Id,
            renewBeforeDays: 30,
            checkIntervalMinutes: 720,
            enabled: true,
            testStart.AddDays(30),
            testStart,
            testStart);
        store.SaveDeploymentPlan(deploymentPlan);
        store.SaveDeploymentPlan(deploymentPlan);
        store.SaveRenewalPolicy(renewalPolicy);
        store.SaveRenewalPolicy(renewalPolicy);

        var issuanceProfile = new TargetIssuanceProfile(
            fixture.Target.Id,
            new Uri("https://acme-staging-v02.api.letsencrypt.org/directory"),
            new AcmeContactUri("operator@example.com"),
            termsAccepted: true,
            testStart,
            "vault://acme/accounts/staging",
            accountUri: null,
            testStart,
            testStart);
        store.SaveTargetIssuanceProfile(issuanceProfile);
        store.SaveTargetIssuanceProfile(issuanceProfile);

        var storedConnection = store.FindConnection(fixture.Connection.Id);
        Assert.IsNotNull(storedConnection);
        Assert.AreEqual("ssh-ed25519", storedConnection.HostKeyAlgorithm);
        CollectionAssert.AreEqual(
            fixture.Connection.ExportRawHostKey(),
            storedConnection.ExportRawHostKey());
        var storedTarget = store.FindTarget(fixture.Target.Id);
        Assert.IsNotNull(storedTarget);
        Assert.AreEqual(fixture.Target.PrimaryName, storedTarget.PrimaryName);
        CollectionAssert.AreEqual(
            fixture.Target.Names.Select(item => item.Value).ToArray(),
            storedTarget.Names.Select(item => item.Value).ToArray());
        Assert.AreEqual(
            deploymentPlan,
            store.FindDeploymentPlan(deploymentPlan.Id));
        Assert.AreEqual(
            deploymentPlan,
            store.FindEnabledDeploymentPlan(fixture.Target.Id));
        Assert.AreEqual(renewalPolicy, store.FindRenewalPolicy(renewalPolicy.Id));
        Assert.AreEqual(
            renewalPolicy,
            store.FindRenewalPolicyByTarget(fixture.Target.Id));
        Assert.AreEqual(
            renewalPolicy,
            store.FindEnabledRenewalPolicy(fixture.Target.Id));
        Assert.AreEqual(
            issuanceProfile,
            store.FindTargetIssuanceProfile(fixture.Target.Id));
        var disabledPolicy = new RenewalPolicy(
            renewalPolicy.Id,
            renewalPolicy.TargetId,
            renewalPolicy.RenewBeforeDays,
            renewalPolicy.CheckIntervalMinutes,
            enabled: false,
            renewalPolicy.NextDueAtUtc,
            renewalPolicy.CreatedAtUtc,
            testStart.AddMinutes(1));
        store.SaveRenewalPolicy(disabledPolicy);
        Assert.AreEqual(
            disabledPolicy,
            store.FindRenewalPolicyByTarget(fixture.Target.Id));
        Assert.IsNull(store.FindEnabledRenewalPolicy(fixture.Target.Id));

        using var connection = OpenReadOnly(databasePath);
        Assert.AreEqual(1L, ReadInt64(connection, "SELECT COUNT(*) FROM connections;"));
        Assert.AreEqual(1L, ReadInt64(connection, "SELECT COUNT(*) FROM targets;"));
        Assert.AreEqual(2L, ReadInt64(connection, "SELECT COUNT(*) FROM target_names;"));
        Assert.AreEqual(
            1L,
            ReadInt64(connection, "SELECT COUNT(*) FROM target_names WHERE is_primary = 1;"));
        Assert.AreEqual(1L, ReadInt64(connection, "SELECT COUNT(*) FROM deployment_plans;"));
        Assert.AreEqual(1L, ReadInt64(connection, "SELECT COUNT(*) FROM renewal_policies;"));
        Assert.AreEqual(
            1L,
            ReadInt64(connection, "SELECT COUNT(*) FROM target_issuance_profiles;"));
    }

    [TestMethod]
    public void OperationCreationIsIdempotentAndAllowsOnlyOneActivePerTarget()
    {
        var (store, _) = CreateStore();
        var firstFixture = CreateTargetFixture(store, 1);
        var secondFixture = CreateTargetFixture(store, 2, firstFixture.Connection);
        var first = RenewalOperation.CreateQueued(
            new OperationId(Guid.Parse("06fed697-0fd5-4344-9806-8286f800c469")),
            firstFixture.Target.Id,
            "renewal-request-one",
            testStart);
        var duplicate = RenewalOperation.CreateQueued(
            new OperationId(Guid.Parse("6190f253-7ec0-4432-bb19-ce25318fd1e8")),
            firstFixture.Target.Id,
            "renewal-request-one",
            testStart.AddMinutes(1));

        Assert.AreEqual(first.Id, store.CreateOrGetOperation(first).Id);
        Assert.AreEqual(first.Id, store.CreateOrGetOperation(duplicate).Id);
        Assert.ThrowsExactly<ProductionOperationAlreadyActiveException>(
            () => store.CreateOrGetOperation(
                RenewalOperation.CreateQueued(
                    OperationId.Create(),
                    firstFixture.Target.Id,
                    "renewal-request-two",
                    testStart.AddMinutes(2))));

        var otherTargetOperation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                secondFixture.Target.Id,
                "renewal-request-other-target",
                testStart.AddMinutes(2)));
        Assert.AreEqual(secondFixture.Target.Id, otherTargetOperation.TargetId);
        var activeOperations = store.ListActiveOperations(maximumCount: 2);
        Assert.HasCount(2, activeOperations);
        Assert.AreEqual(first.Id, activeOperations[0].Id);
        Assert.HasCount(1, store.ListActiveOperations(maximumCount: 1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => store.ListActiveOperations(maximumCount: 0));
        Assert.ThrowsExactly<ProductionIdempotencyConflictException>(
            () => store.CreateOrGetOperation(
                RenewalOperation.CreateQueued(
                    OperationId.Create(),
                    secondFixture.Target.Id,
                    "renewal-request-one",
                    testStart.AddMinutes(3))));
    }

    [TestMethod]
    public void SuccessRequiresDurableVerificationAndCleanupEvidence()
    {
        var (store, databasePath) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                new OperationId(Guid.Parse("d25667f0-d519-4bbd-abfc-640023cc5101")),
                fixture.Target.Id,
                "renewal-success-invariant",
                testStart));
        var executionEpoch = Guid.Parse("fc28fc23-f13f-4b38-a209-c8dacd66accc");
        _ = store.TryStartOperation(
            operation.Id,
            executionEpoch,
            testStart.AddSeconds(30));

        Assert.ThrowsExactly<ProductionOperationInvariantException>(
            () => store.CompleteOwnedOperation(
                operation.Id,
                executionEpoch,
                OperationStatus.Running,
                OperationStatus.Succeeded,
                testStart.AddMinutes(1)));
        _ = store.AppendOperationEvidence(
            operation.Id,
            OperationEvidenceKind.Verification,
            stage: null,
            OperationEvidenceOutcome.Succeeded,
            testStart.AddMinutes(2),
            "public_tls.verified",
            "One public TLS probe passed, but the aggregate is not complete.");
        Assert.ThrowsExactly<ProductionOperationInvariantException>(
            () => store.CompleteOwnedOperation(
                operation.Id,
                executionEpoch,
                OperationStatus.Running,
                OperationStatus.Succeeded,
                testStart.AddMinutes(3)));
        _ = store.AppendOperationEvidence(
            operation.Id,
            OperationEvidenceKind.Cleanup,
            stage: null,
            OperationEvidenceOutcome.Succeeded,
            testStart.AddMinutes(4),
            "challenge.cleaned",
            "One challenge artifact was removed, but cleanup is not complete.");

        Assert.ThrowsExactly<ProductionOperationInvariantException>(
            () => store.CompleteOwnedOperation(
                operation.Id,
                executionEpoch,
                OperationStatus.Running,
                OperationStatus.Succeeded,
                testStart.AddMinutes(5)));
        _ = store.AppendOperationEvidence(
            operation.Id,
            OperationEvidenceKind.Verification,
            stage: null,
            OperationEvidenceOutcome.Succeeded,
            testStart.AddMinutes(5),
            "tls.all_names_verified",
            "Every requested DNS name serves the expected certificate.");
        _ = store.AppendOperationEvidence(
            operation.Id,
            OperationEvidenceKind.Cleanup,
            stage: null,
            OperationEvidenceOutcome.Succeeded,
            testStart.AddMinutes(6),
            "challenge.cleanup_complete",
            "All owned challenge artifacts were removed.");

        var completed = store.CompleteOwnedOperation(
            operation.Id,
            executionEpoch,
            OperationStatus.Running,
            OperationStatus.Succeeded,
            testStart.AddMinutes(7));
        Assert.AreEqual(OperationStatus.Succeeded, completed.Status);
        CollectionAssert.AreEqual(
            new long[] { 1, 2, 3, 4 },
            store.ReadOperationEvidence(operation.Id).Select(item => item.Sequence).ToArray());

        using var connection = OpenReadWrite(databasePath);
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            DELETE FROM operation_evidence
            WHERE operation_id = $operation_id
              AND kind = 'Verification';
            """;
        command.Parameters.AddWithValue(
            "$operation_id",
            operation.Id.Value.ToString("D", CultureInfo.InvariantCulture));
        Assert.ThrowsExactly<SqliteException>(() => command.ExecuteNonQuery());
    }

    [TestMethod]
    public void OperationIntentCreationIsIdempotent()
    {
        var (store, _) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                fixture.Target.Id,
                "intent-operation",
                testStart));
        var intent = new OperationIntent(
            new OperationIntentId(Guid.Parse("050ca4df-36af-4cda-80df-7aa75ea20507")),
            operation.Id,
            sequence: 1,
            OperationIntentKind.ChallengeWrite,
            "intent-challenge-write",
            OperationIntentStatus.Planned,
            testStart,
            remotePath: "/var/www/challenges/token-a");
        var duplicate = new OperationIntent(
            OperationIntentId.Create(),
            operation.Id,
            sequence: 1,
            OperationIntentKind.ChallengeWrite,
            "intent-challenge-write",
            OperationIntentStatus.Planned,
            testStart.AddMinutes(1),
            remotePath: "/var/www/challenges/token-a");

        Assert.AreEqual(intent.Id, store.CreateOrGetOperationIntent(intent).Id);
        Assert.AreEqual(intent.Id, store.CreateOrGetOperationIntent(duplicate).Id);
    }

    [TestMethod]
    public void V4RemoteHelperIntentKindsAreDurable()
    {
        var (store, _) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                fixture.Target.Id,
                "remote-helper-intent-kinds",
                testStart));
        var kinds = new[]
        {
            OperationIntentKind.RemotePrepare,
            OperationIntentKind.RemoteVerify,
            OperationIntentKind.Commit,
            OperationIntentKind.Abort,
        };

        for (var index = 0; index < kinds.Length; index++)
        {
            _ = store.CreateOrGetOperationIntent(
                new OperationIntent(
                    OperationIntentId.Create(),
                    operation.Id,
                    index + 1,
                    kinds[index],
                    $"remote-helper-intent-{index + 1}",
                    OperationIntentStatus.Planned,
                    testStart.AddSeconds(index)));
        }

        CollectionAssert.AreEqual(
            kinds,
            store.ReadOperationIntents(operation.Id).Select(item => item.Kind).ToArray());
    }

    [TestMethod]
    public void OwnedOperationAndIntentTransitionsAreOptimisticAndIdempotent()
    {
        var (store, _) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                fixture.Target.Id,
                "owned-operation",
                testStart));
        var executionEpoch = Guid.Parse("e3bc2542-aef9-4a3f-9ba8-154988f02653");

        var started = store.TryStartOperation(
            operation.Id,
            executionEpoch,
            testStart.AddMinutes(1));
        Assert.IsNotNull(started);
        Assert.AreEqual(OperationStatus.Running, started.Status);
        Assert.AreEqual(executionEpoch, started.ExecutionEpoch);
        Assert.AreEqual(
            started,
            store.TryStartOperation(
                operation.Id,
                executionEpoch,
                testStart.AddMinutes(2)));
        Assert.IsNull(
            store.TryStartOperation(
                operation.Id,
                Guid.NewGuid(),
                testStart.AddMinutes(2)));

        var blocked = store.TransitionOwnedOperationStatus(
            operation.Id,
            executionEpoch,
            OperationStatus.Running,
            OperationStatus.Blocked,
            testStart.AddMinutes(2),
            "remote.access_blocked");
        Assert.AreEqual(OperationStatus.Blocked, blocked.Status);
        Assert.AreEqual(
            blocked,
            store.TransitionOwnedOperationStatus(
                operation.Id,
                executionEpoch,
                OperationStatus.Running,
                OperationStatus.Blocked,
                testStart.AddMinutes(3),
                "remote.access_blocked"));
        Assert.ThrowsExactly<ProductionOperationStateConflictException>(
            () => store.TransitionOwnedOperationStatus(
                operation.Id,
                Guid.NewGuid(),
                OperationStatus.Blocked,
                OperationStatus.RollbackRequired,
                testStart.AddMinutes(3),
                "deployment.rollback_required"));

        var intent = store.CreateOrGetOperationIntent(
            new OperationIntent(
                OperationIntentId.Create(),
                operation.Id,
                sequence: 1,
                OperationIntentKind.CertificateDeploy,
                "owned-intent-deploy",
                OperationIntentStatus.Planned,
                testStart.AddMinutes(2)));
        var uncertain = store.TransitionOwnedOperationIntentStatus(
            intent.Id,
            executionEpoch,
            OperationIntentStatus.Planned,
            OperationIntentStatus.Uncertain,
            testStart.AddMinutes(3));
        Assert.AreEqual(OperationIntentStatus.Uncertain, uncertain.Status);
        var reconciled = store.TransitionOwnedOperationIntentStatus(
            intent.Id,
            executionEpoch,
            OperationIntentStatus.Uncertain,
            OperationIntentStatus.Reconciled,
            testStart.AddMinutes(4));
        Assert.AreEqual(OperationIntentStatus.Reconciled, reconciled.Status);
        Assert.AreEqual(testStart.AddMinutes(4), reconciled.AppliedAtUtc);
        Assert.AreEqual(reconciled, store.FindOperationIntent(intent.Id));
        Assert.AreEqual(
            reconciled,
            store.FindOperationIntentByIdempotencyKey(intent.IdempotencyKey));
        CollectionAssert.AreEqual(
            new[] { reconciled },
            store.ReadOperationIntents(operation.Id).ToArray());
        Assert.ThrowsExactly<ProductionOperationStateConflictException>(
            () => store.CompleteOwnedOperation(
                operation.Id,
                Guid.NewGuid(),
                OperationStatus.Blocked,
                OperationStatus.Failed,
                testStart.AddMinutes(5),
                "deployment.failed"));
        var completed = store.CompleteOwnedOperation(
            operation.Id,
            executionEpoch,
            OperationStatus.Blocked,
            OperationStatus.Failed,
            testStart.AddMinutes(5),
            "deployment.failed");
        Assert.AreEqual(OperationStatus.Failed, completed.Status);
    }

    [TestMethod]
    public void ManualActorAuditEventsAreDurableIdempotentAndBounded()
    {
        var (store, databasePath) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                fixture.Target.Id,
                "manual-audit-operation",
                testStart));
        var auditEventId = new AuditEventId(
            Guid.Parse("3464feaa-7e9d-4c1b-bc48-0762e4c9b1af"));
        var appended = store.AppendAuditEvent(
            auditEventId,
            operation.Id,
            fixture.Target.Id,
            "S-1-5-21-111111111-222222222-333333333-1001",
            "renewal.requested",
            testStart.AddMinutes(1),
            "renewal.manual_request",
            "An administrator requested a live renewal.");

        Assert.AreEqual(1L, appended.Sequence);
        Assert.AreEqual(
            appended,
            store.AppendAuditEvent(
                auditEventId,
                operation.Id,
                fixture.Target.Id,
                appended.ActorSid,
                appended.EventType,
                appended.OccurredAtUtc,
                appended.Code,
                appended.Description));
        Assert.ThrowsExactly<ProductionAuditEventConflictException>(
            () => store.AppendAuditEvent(
                auditEventId,
                operation.Id,
                fixture.Target.Id,
                appended.ActorSid,
                appended.EventType,
                appended.OccurredAtUtc,
                appended.Code,
                "A different immutable description."));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => store.ReadAuditEvents(maximumCount: 0));
        Assert.HasCount(1, store.ReadAuditEvents(maximumCount: 1));
        Assert.HasCount(
            0,
            store.ReadAuditEvents(maximumCount: 1, afterSequence: appended.Sequence));

        var reopened = new SqliteProductionStore(databasePath);
        reopened.Initialize(testStart.AddMinutes(2));
        Assert.AreEqual(appended, reopened.ReadAuditEvents(maximumCount: 1).Single());
    }

    [TestMethod]
    public void AcmeAccountRegistrationPreservesOpaqueKeyReference()
    {
        var (store, _) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        var directoryUri =
            new Uri("https://acme-staging-v02.api.letsencrypt.org/directory");
        store.SaveTargetIssuanceProfile(
            new TargetIssuanceProfile(
                fixture.Target.Id,
                directoryUri,
                new AcmeContactUri("operator@example.com"),
                termsAccepted: true,
                testStart,
                "vault://acme/accounts/staging",
                accountUri: null,
                testStart,
                testStart));
        var pending = new AcmeAccountRecord(
            new AcmeAccountId(Guid.Parse("4c7b25a4-9fef-4b5d-9791-e4b502be0005")),
            directoryUri,
            accountUri: null,
            "operator@example.com",
            "vault://acme/accounts/staging",
            AcmeAccountStatus.Pending,
            testStart,
            testStart);
        var duplicate = new AcmeAccountRecord(
            AcmeAccountId.Create(),
            directoryUri,
            accountUri: null,
            "operator@example.com",
            "vault://acme/accounts/staging",
            AcmeAccountStatus.Pending,
            testStart.AddMinutes(1),
            testStart.AddMinutes(1));

        Assert.AreEqual(pending.Id, store.CreateOrGetAcmeAccount(pending).Id);
        Assert.AreEqual(pending.Id, store.CreateOrGetAcmeAccount(duplicate).Id);
        Assert.IsNull(store.FindPreferredValidAcmeAccount(directoryUri));
        var accountUri = new Uri("https://acme.example/acct/12345");
        var valid = store.UpdateAcmeAccountRegistration(
            pending.Id,
            AcmeAccountStatus.Pending,
            accountUri,
            AcmeAccountStatus.Valid,
            testStart.AddMinutes(2));
        Assert.AreEqual(accountUri, valid.AccountUri);
        Assert.AreEqual("vault://acme/accounts/staging", valid.KeySecretReference);
        Assert.AreEqual(valid, store.FindPreferredValidAcmeAccount(directoryUri));
        Assert.AreEqual(
            accountUri,
            store.FindTargetIssuanceProfile(fixture.Target.Id)?.AccountUri);
        Assert.AreEqual(
            valid,
            store.UpdateAcmeAccountRegistration(
                pending.Id,
                AcmeAccountStatus.Pending,
                accountUri,
                AcmeAccountStatus.Valid,
                testStart.AddMinutes(3)));
        Assert.ThrowsExactly<ProductionAcmeAccountStateConflictException>(
            () => store.UpdateAcmeAccountRegistration(
                pending.Id,
                AcmeAccountStatus.Pending,
                accountUri,
                AcmeAccountStatus.Revoked,
                testStart.AddMinutes(3)));
    }

    [TestMethod]
    public void ExactAcmeAccountLookupSeparatesTargetsUsingTheSameDirectory()
    {
        var (store, _) = CreateStore();
        var firstFixture = CreateTargetFixture(store, 1);
        var secondFixture = CreateTargetFixture(store, 2, firstFixture.Connection);
        var directoryUri =
            new Uri("https://acme-staging-v02.api.letsencrypt.org/directory");
        const string firstSecretReference =
            "0e78df93-c62a-485b-97f8-788de616471f";
        const string secondSecretReference =
            "19938f5f-e9d2-48f4-a2ac-4c7955b20975";
        store.SaveTargetIssuanceProfile(
            new TargetIssuanceProfile(
                firstFixture.Target.Id,
                directoryUri,
                new AcmeContactUri("first@example.com"),
                termsAccepted: true,
                testStart,
                firstSecretReference,
                new Uri("https://acme.example/acct/first"),
                testStart,
                testStart));
        store.SaveTargetIssuanceProfile(
            new TargetIssuanceProfile(
                secondFixture.Target.Id,
                directoryUri,
                new AcmeContactUri("second@example.com"),
                termsAccepted: true,
                testStart,
                secondSecretReference,
                new Uri("https://acme.example/acct/second"),
                testStart,
                testStart.AddMinutes(1)));
        var first = store.CreateOrGetAcmeAccount(
            new AcmeAccountRecord(
                new AcmeAccountId(Guid.Parse(firstSecretReference)),
                directoryUri,
                new Uri("https://acme.example/acct/first"),
                "first@example.com",
                firstSecretReference,
                AcmeAccountStatus.Valid,
                testStart,
                testStart));
        var second = store.CreateOrGetAcmeAccount(
            new AcmeAccountRecord(
                new AcmeAccountId(Guid.Parse(secondSecretReference)),
                directoryUri,
                new Uri("https://acme.example/acct/second"),
                "second@example.com",
                secondSecretReference,
                AcmeAccountStatus.Valid,
                testStart,
                testStart.AddMinutes(1)));

        Assert.AreEqual(
            first,
            store.FindAcmeAccount(directoryUri, firstSecretReference));
        Assert.AreEqual(
            second,
            store.FindAcmeAccount(directoryUri, secondSecretReference));
        Assert.AreEqual(second, store.FindPreferredValidAcmeAccount(directoryUri));
        Assert.IsNull(
            store.FindAcmeAccount(
                directoryUri,
                "5b0dd51a-4f27-440a-b1c7-536033883613"));
    }

    [TestMethod]
    public void EnrollmentSaveIsAtomicBoundedAndRejectsIdentityChanges()
    {
        var (store, databasePath) = CreateStore();
        var enrollmentId = new EnrollmentId(
            Guid.Parse("b368fc5e-5f82-46e8-b907-ce749efbe1da"));
        var enrollment = BuildEnrollment(1, enrollmentId);

        store.SaveEnrollment(enrollment);
        store.SaveEnrollment(enrollment);
        var targets = store.ListTargets(maximumCount: 1);
        Assert.HasCount(1, targets);
        Assert.AreEqual(enrollment.Target.Id, targets[0].Id);
        Assert.HasCount(
            0,
            store.ListTargets(
                maximumCount: 1,
                afterTargetId: enrollment.Target.Id));

        var changedCredential = BuildEnrollment(
            1,
            enrollmentId,
            credentialReference: "vault://connections/changed-credential");
        Assert.ThrowsExactly<ProductionEnrollmentConflictException>(
            () => store.SaveEnrollment(changedCredential));
        Assert.AreEqual(
            enrollment.Connection.CredentialReference,
            store.FindConnection(enrollment.Connection.Id)?.CredentialReference);

        var collidingEnrollment = BuildEnrollment(
            2,
            EnrollmentId.Create(),
            primaryName: enrollment.Target.PrimaryName.Value);
        Assert.ThrowsExactly<SqliteException>(
            () => store.SaveEnrollment(collidingEnrollment));
        Assert.IsNull(store.FindConnection(collidingEnrollment.Connection.Id));
        Assert.IsNull(store.FindTarget(collidingEnrollment.Target.Id));
        using var connection = OpenReadOnly(databasePath);
        Assert.AreEqual(1L, ReadInt64(connection, "SELECT COUNT(*) FROM enrollments;"));
    }

    [TestMethod]
    public void CertificateArtifactRoundTripsAcrossRestartAndTransitionsOptimistically()
    {
        var (store, databasePath) = CreateStore();
        var fixture = CreateTargetFixture(store, 1);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                fixture.Target.Id,
                "artifact-operation",
                testStart));
        var artifact = new CertificateArtifact(
            new CertificateArtifactId(
                Guid.Parse("932a09ae-ad02-4be3-b10e-46b55c051291")),
            operation.Id,
            new Sha256Digest(new string('A', 64)),
            new Sha256Digest(new string('B', 64)),
            "vault://certificates/artifact-operation/private-key",
            testStart.AddHours(-1),
            testStart.AddDays(90),
            CertificateArtifactStatus.Issued,
            testStart);
        var duplicate = new CertificateArtifact(
            CertificateArtifactId.Create(),
            operation.Id,
            artifact.CertificateSha256,
            artifact.PublicKeySha256,
            artifact.PrivateKeySecretReference,
            artifact.NotBeforeUtc,
            artifact.NotAfterUtc,
            CertificateArtifactStatus.Issued,
            testStart.AddMinutes(1));

        Assert.AreEqual(artifact.Id, store.CreateOrGetCertificateArtifact(artifact).Id);
        Assert.AreEqual(artifact.Id, store.CreateOrGetCertificateArtifact(duplicate).Id);
        var deployed = store.TransitionCertificateArtifactStatus(
            artifact.Id,
            CertificateArtifactStatus.Issued,
            CertificateArtifactStatus.Deployed);
        Assert.AreEqual(CertificateArtifactStatus.Deployed, deployed.Status);
        Assert.ThrowsExactly<ProductionCertificateArtifactStateConflictException>(
            () => store.TransitionCertificateArtifactStatus(
                artifact.Id,
                CertificateArtifactStatus.Issued,
                CertificateArtifactStatus.Revoked));

        var reopened = new SqliteProductionStore(databasePath);
        reopened.Initialize(testStart.AddMinutes(2));
        Assert.AreEqual(operation, reopened.FindOperation(operation.Id));
        var persistedArtifact = reopened.FindCertificateArtifact(operation.Id);
        Assert.IsNotNull(persistedArtifact);
        Assert.AreEqual(deployed, persistedArtifact);
        Assert.AreEqual(
            "vault://certificates/artifact-operation/private-key",
            persistedArtifact.PrivateKeySecretReference);
    }

    [TestMethod]
    public void OwnedLiveRenewalCompletionIsAtomicAcrossArtifactPolicyAndOperation()
    {
        var (store, databasePath) = CreateStore();
        var enrollment = BuildEnrollment(1, EnrollmentId.Create());
        store.SaveEnrollment(enrollment);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                enrollment.Target.Id,
                "atomic-live-completion",
                testStart));
        var executionEpoch = Guid.Parse("2ade117c-dcf3-49ea-b266-93274d74222b");
        _ = store.TryStartOperation(
            operation.Id,
            executionEpoch,
            testStart.AddMinutes(1));
        var artifact = store.CreateOrGetCertificateArtifact(
            new CertificateArtifact(
                CertificateArtifactId.Create(),
                operation.Id,
                new Sha256Digest(new string('C', 64)),
                new Sha256Digest(new string('D', 64)),
                "6bb77557-8975-43cb-b3b6-d53210982c70",
                testStart.AddHours(-1),
                testStart.AddDays(90),
                CertificateArtifactStatus.Issued,
                testStart.AddMinutes(2)));
        _ = store.AppendOperationEvidence(
            operation.Id,
            OperationEvidenceKind.Verification,
            stage: null,
            OperationEvidenceOutcome.Succeeded,
            testStart.AddMinutes(3),
            "tls.all_names_verified",
            "Every requested DNS name serves the expected certificate.");
        _ = store.AppendOperationEvidence(
            operation.Id,
            OperationEvidenceKind.Cleanup,
            stage: null,
            OperationEvidenceOutcome.Succeeded,
            testStart.AddMinutes(4),
            "challenge.cleanup_complete",
            "All owned challenge artifacts were removed.");
        _ = store.CreateOrGetOperationIntent(
            new OperationIntent(
                OperationIntentId.Create(),
                operation.Id,
                sequence: 1,
                OperationIntentKind.Commit,
                "atomic-live-commit",
                OperationIntentStatus.Applied,
                testStart.AddMinutes(4),
                testStart.AddMinutes(4)));
        var completedAt = testStart.AddMinutes(5);
        var nextDueAt = artifact.NotAfterUtc.AddDays(-30);

        using (var connection = OpenReadWrite(databasePath))
        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                """
                CREATE TRIGGER test_force_live_completion_conflict
                BEFORE UPDATE OF status ON operations
                WHEN NEW.status = 'Succeeded'
                BEGIN
                    SELECT RAISE(ABORT, 'forced live completion conflict');
                END;
                """;
            _ = command.ExecuteNonQuery();
        }

        Assert.ThrowsExactly<SqliteException>(
            () => store.CompleteOwnedLiveRenewal(
                operation.Id,
                executionEpoch,
                OperationStatus.Running,
                OperationStatus.Succeeded,
                completedAt,
                nextDueAt));
        Assert.AreEqual(
            OperationStatus.Running,
            store.FindOperation(operation.Id)?.Status);
        Assert.AreEqual(
            CertificateArtifactStatus.Issued,
            store.FindCertificateArtifact(operation.Id)?.Status);
        Assert.IsNull(
            store.FindRenewalPolicy(enrollment.RenewalPolicy.Id)?.NextDueAtUtc);

        using (var connection = OpenReadWrite(databasePath))
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "DROP TRIGGER test_force_live_completion_conflict;";
            _ = command.ExecuteNonQuery();
        }

        var completed = store.CompleteOwnedLiveRenewal(
            operation.Id,
            executionEpoch,
            OperationStatus.Running,
            OperationStatus.Succeeded,
            completedAt,
            nextDueAt);
        Assert.AreEqual(OperationStatus.Succeeded, completed.Status);
        Assert.AreEqual(
            CertificateArtifactStatus.Deployed,
            store.FindCertificateArtifact(operation.Id)?.Status);
        Assert.AreEqual(
            nextDueAt,
            store.FindRenewalPolicy(enrollment.RenewalPolicy.Id)?.NextDueAtUtc);
        Assert.AreEqual(
            completed,
            store.CompleteOwnedLiveRenewal(
                operation.Id,
                executionEpoch,
                OperationStatus.Running,
                OperationStatus.Succeeded,
                completedAt,
                nextDueAt));
        Assert.ThrowsExactly<ProductionOperationStateConflictException>(
            () => store.CompleteOwnedLiveRenewal(
                operation.Id,
                executionEpoch,
                OperationStatus.Running,
                OperationStatus.Succeeded,
                completedAt,
                nextDueAt.AddMinutes(1)));
    }

    [TestMethod]
    public void SuccessfulLiveCompletionRequiresCommitAndEveryChallengeReconciled()
    {
        var (store, _) = CreateStore();
        var enrollment = BuildEnrollment(1, EnrollmentId.Create());
        store.SaveEnrollment(enrollment);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                enrollment.Target.Id,
                "live-success-intent-invariants",
                testStart));
        var executionEpoch = Guid.CreateVersion7();
        _ = store.TryStartOperation(
            operation.Id,
            executionEpoch,
            testStart.AddMinutes(1));
        var artifact = store.CreateOrGetCertificateArtifact(
            new CertificateArtifact(
                CertificateArtifactId.Create(),
                operation.Id,
                new Sha256Digest(new string('E', 64)),
                new Sha256Digest(new string('F', 64)),
                Guid.CreateVersion7().ToString("D"),
                testStart.AddHours(-1),
                testStart.AddDays(7),
                CertificateArtifactStatus.Issued,
                testStart.AddMinutes(2)));
        _ = store.AppendOperationEvidence(
            operation.Id,
            OperationEvidenceKind.Verification,
            stage: null,
            OperationEvidenceOutcome.Succeeded,
            testStart.AddMinutes(3),
            "tls.all_names_verified",
            "Every configured DNS name was verified.");
        _ = store.AppendOperationEvidence(
            operation.Id,
            OperationEvidenceKind.Cleanup,
            stage: null,
            OperationEvidenceOutcome.Succeeded,
            testStart.AddMinutes(3),
            "challenge.cleanup_complete",
            "Every challenge path was cleaned.");
        var completedAt = testStart.AddMinutes(5);
        var nextDueAt = artifact.NotAfterUtc.AddDays(-2);

        Assert.ThrowsExactly<ProductionOperationInvariantException>(
            () => store.CompleteOwnedLiveRenewal(
                operation.Id,
                executionEpoch,
                OperationStatus.Running,
                OperationStatus.Succeeded,
                completedAt,
                nextDueAt));
        Assert.AreEqual(OperationStatus.Running, store.FindOperation(operation.Id)?.Status);
        Assert.AreEqual(CertificateArtifactStatus.Issued, store.FindCertificateArtifact(operation.Id)?.Status);

        _ = store.CreateOrGetOperationIntent(
            new OperationIntent(
                OperationIntentId.Create(),
                operation.Id,
                sequence: 1,
                OperationIntentKind.Commit,
                "live-success-commit",
                OperationIntentStatus.Applied,
                testStart.AddMinutes(4),
                testStart.AddMinutes(4)));
        var challenge = store.CreateOrGetOperationIntent(
            new OperationIntent(
                OperationIntentId.Create(),
                operation.Id,
                sequence: 2,
                OperationIntentKind.ChallengeWrite,
                "live-success-challenge",
                OperationIntentStatus.Planned,
                testStart.AddMinutes(4),
                remotePath: "/srv/www/.well-known/acme-challenge/token"));
        Assert.ThrowsExactly<ProductionOperationInvariantException>(
            () => store.CompleteOwnedLiveRenewal(
                operation.Id,
                executionEpoch,
                OperationStatus.Running,
                OperationStatus.Succeeded,
                completedAt,
                nextDueAt));

        _ = store.TransitionOwnedOperationIntentStatus(
            challenge.Id,
            executionEpoch,
            OperationIntentStatus.Planned,
            OperationIntentStatus.Reconciled,
            testStart.AddMinutes(4));
        var completed = store.CompleteOwnedLiveRenewal(
            operation.Id,
            executionEpoch,
            OperationStatus.Running,
            OperationStatus.Succeeded,
            completedAt,
            nextDueAt);
        Assert.AreEqual(OperationStatus.Succeeded, completed.Status);
        Assert.AreEqual(CertificateArtifactStatus.Deployed, store.FindCertificateArtifact(operation.Id)?.Status);
    }

    [TestMethod]
    [DataRow(OperationStatus.Failed)]
    [DataRow(OperationStatus.Cancelled)]
    [DataRow(OperationStatus.Interrupted)]
    public void OwnedLiveRenewalTerminalFailureAtomicallyReschedules(
        OperationStatus terminalStatus)
    {
        var (store, _) = CreateStore();
        var enrollment = BuildEnrollment(1, EnrollmentId.Create());
        store.SaveEnrollment(enrollment);
        var operation = store.CreateOrGetOperation(
            RenewalOperation.CreateQueued(
                OperationId.Create(),
                enrollment.Target.Id,
                $"atomic-live-{terminalStatus}",
                testStart));
        var executionEpoch = Guid.NewGuid();
        _ = store.TryStartOperation(
            operation.Id,
            executionEpoch,
            testStart.AddMinutes(1));
        var completedAt = testStart.AddMinutes(2);
        var nextDueAt = testStart.AddHours(12);

        var completed = store.CompleteOwnedLiveRenewal(
            operation.Id,
            executionEpoch,
            OperationStatus.Running,
            terminalStatus,
            completedAt,
            nextDueAt,
            "live.test_terminal");

        Assert.AreEqual(terminalStatus, completed.Status);
        Assert.AreEqual("live.test_terminal", completed.FailureCode);
        Assert.AreEqual(
            nextDueAt,
            store.FindRenewalPolicy(enrollment.RenewalPolicy.Id)?.NextDueAtUtc);
        Assert.IsNull(store.FindCertificateArtifact(operation.Id));
    }

    private (SqliteProductionStore Store, string DatabasePath) CreateStore()
    {
        var directory = CreateTestDirectory();
        var databasePath = Path.Combine(directory, "state.db");
        var store = new SqliteProductionStore(databasePath);
        store.Initialize(testStart);
        return (store, databasePath);
    }

    private static TargetFixture CreateTargetFixture(
        SqliteProductionStore store,
        int number,
        ConnectionProfile? sharedConnection = null)
    {
        var rawHostKey = Encoding.UTF8.GetBytes("fixture-public-ssh-host-key");
        var hostKeyFingerprint =
            "SHA256:" +
            Convert.ToBase64String(SHA256.HashData(rawHostKey)).TrimEnd('=');
        var connection = sharedConnection ?? new ConnectionProfile(
            new ConnectionId(Guid.Parse("8d2d9ca6-e4f9-4ea7-a64d-b02050ed13ef")),
            "Test SSH connection",
            new ConnectionEndpoint("ssh.example.com"),
            "deploy",
            "vault://connections/test-ssh",
            "ssh-ed25519",
            hostKeyFingerprint,
            testStart,
            testStart,
            enabled: true,
            rawHostKey);
        store.SaveConnection(connection);
        var targetId = number == 1
            ? Guid.Parse("bc2db471-c39f-4909-88d7-6e10a60e4c38")
            : Guid.Parse("e21f202b-ee23-41e0-a12f-7278dc5edc79");
        var target = new CertificateTarget(
            new TargetId(targetId),
            connection.Id,
            $"Test website {number}",
            new TargetDnsName($"site{number}.example.com"),
            [new TargetDnsName($"www.site{number}.example.com")],
            TargetLifecycleStatus.Ready,
            testStart,
            testStart);
        store.SaveTarget(target);
        return new TargetFixture(connection, target);
    }

    private static TargetEnrollment BuildEnrollment(
        int number,
        EnrollmentId enrollmentId,
        string credentialReference = "vault://connections/enrolled",
        string? primaryName = null)
    {
        var rawHostKey = Encoding.UTF8.GetBytes($"enrollment-public-host-key-{number}");
        var fingerprint =
            "SHA256:" +
            Convert.ToBase64String(SHA256.HashData(rawHostKey)).TrimEnd('=');
        var connectionId = number == 1
            ? Guid.Parse("4b55e10f-e4b2-4440-950e-bfe1715843d3")
            : Guid.Parse("d60814ea-a2c1-4e71-9fd1-eaf51d5644d9");
        var targetId = number == 1
            ? Guid.Parse("acb70590-7d67-430d-b01f-c2f76ca5bfcb")
            : Guid.Parse("62023b19-c9cb-40c3-8247-9076e6482374");
        var connection = new ConnectionProfile(
            new ConnectionId(connectionId),
            $"Enrolled connection {number}",
            new ConnectionEndpoint($"ssh{number}.example.com"),
            "deploy",
            credentialReference,
            "ssh-ed25519",
            fingerprint,
            testStart,
            testStart,
            enabled: true,
            rawHostKey);
        var target = new CertificateTarget(
            new TargetId(targetId),
            connection.Id,
            $"Enrolled website {number}",
            new TargetDnsName(primaryName ?? $"enrolled{number}.example.com"),
            [],
            TargetLifecycleStatus.Ready,
            testStart,
            testStart);
        var deploymentPlan = new DeploymentPlan(
            new DeploymentPlanId(number == 1
                ? Guid.Parse("3af126a2-8b92-4d46-a397-093fd71263ad")
                : Guid.Parse("df143370-7931-46d4-a6a0-d30e61b395f4")),
            target.Id,
            DeploymentKind.Nginx,
            new RemotePath($"/srv/www/enrolled{number}"),
            new RemotePath($"/var/lib/certbaton/incoming/enrolled{number}"),
            new RemotePath($"/etc/nginx/tls/enrolled{number}.pem"),
            new RemotePath($"/etc/nginx/tls/enrolled{number}.key"),
            testStart,
            testStart);
        var renewalPolicy = new RenewalPolicy(
            new RenewalPolicyId(number == 1
                ? Guid.Parse("cc28a779-1e0a-4502-b744-549420f1bc3d")
                : Guid.Parse("4d74da49-edbd-449c-ad24-ac2751869e8e")),
            target.Id,
            renewBeforeDays: 30,
            checkIntervalMinutes: 720,
            enabled: true,
            nextDueAtUtc: null,
            testStart,
            testStart);
        var issuanceProfile = new TargetIssuanceProfile(
            target.Id,
            new Uri("https://acme-staging-v02.api.letsencrypt.org/directory"),
            new AcmeContactUri("operator@example.com"),
            termsAccepted: true,
            testStart,
            $"vault://acme/accounts/enrolled-{number}",
            accountUri: null,
            testStart,
            testStart);
        return new TargetEnrollment(
            enrollmentId,
            connection,
            target,
            deploymentPlan,
            renewalPolicy,
            issuanceProfile,
            testStart);
    }

    private string CreateTestDirectory()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "CertBaton.UnitTests",
            Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(directory);
        testDirectories.Add(directory);
        return directory;
    }

    private static SqliteConnection OpenReadOnly(string databasePath)
    {
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());
        connection.Open();
        return connection;
    }

    private static SqliteConnection OpenReadWrite(string databasePath)
    {
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false,
            }.ToString());
        connection.Open();
        return connection;
    }

    private static void DowngradeFixtureToV1(string databasePath)
    {
        using var connection = OpenReadWrite(databasePath);
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            PRAGMA foreign_keys = OFF;
            DROP TRIGGER operations_reject_inserted_success;
            DROP TRIGGER operations_require_success_evidence;
            DROP TRIGGER operation_evidence_preserve_success_delete;
            DROP TRIGGER operation_evidence_preserve_success_update;
            DROP TRIGGER connections_require_host_key_algorithm_insert;
            DROP TRIGGER connections_require_host_key_algorithm_update;
            DROP TRIGGER deployment_plans_require_incoming_root_insert;
            DROP TRIGGER deployment_plans_require_incoming_root_update;
            DROP TRIGGER operations_validate_ownership_insert;
            DROP TRIGGER operations_validate_ownership_update;
            DROP TRIGGER operation_intents_validate_status_insert;
            DROP TRIGGER operation_intents_validate_status_update;
            DROP TABLE audit_events;
            DROP TABLE tls_probe_evidence;
            DROP TABLE certificate_artifacts;
            DROP TABLE acme_orders;
            DROP TABLE acme_accounts;
            DROP TABLE operation_intents;
            DROP TABLE operation_evidence;
            DROP TABLE operations;
            DROP TABLE enrollments;
            DROP TABLE renewal_policies;
            DROP TABLE deployment_plans;
            DROP TABLE target_issuance_profiles;
            DROP TABLE target_names;
            DROP TABLE targets;
            DROP TABLE connections;
            DELETE FROM schema_migrations WHERE version > 1;
            PRAGMA user_version = 1;
            """;
        _ = command.ExecuteNonQuery();
    }

    private static void DowngradeFixtureToV3(string databasePath)
    {
        using var connection = OpenReadWrite(databasePath);
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            DROP TRIGGER operation_intents_validate_status_insert;
            DROP TRIGGER operation_intents_validate_status_update;

            CREATE TABLE operation_intents_v3 (
                operation_intent_id TEXT NOT NULL PRIMARY KEY
                    CHECK (length(operation_intent_id) = 36),
                operation_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                kind TEXT NOT NULL CHECK (kind IN (
                    'ChallengeWrite', 'CertificateDeploy', 'Activate', 'Rollback'
                )),
                idempotency_key TEXT NOT NULL UNIQUE
                    CHECK (length(idempotency_key) BETWEEN 1 AND 200),
                status TEXT NOT NULL CHECK (status IN (
                    'Planned', 'Applied', 'Reconciled', 'Failed', 'Uncertain'
                )),
                recorded_at_ms INTEGER NOT NULL,
                applied_at_ms INTEGER NULL,
                UNIQUE (operation_id, sequence),
                FOREIGN KEY (operation_id)
                    REFERENCES operations(operation_id) ON DELETE RESTRICT
            ) STRICT;

            INSERT INTO operation_intents_v3 (
                operation_intent_id,
                operation_id,
                sequence,
                kind,
                idempotency_key,
                status,
                recorded_at_ms,
                applied_at_ms
            )
            SELECT
                operation_intent_id,
                operation_id,
                sequence,
                kind,
                idempotency_key,
                status,
                recorded_at_ms,
                applied_at_ms
            FROM operation_intents;

            DROP TABLE operation_intents;
            ALTER TABLE operation_intents_v3 RENAME TO operation_intents;

            CREATE TRIGGER operation_intents_validate_status_insert
            BEFORE INSERT ON operation_intents
            WHEN NEW.status IN ('Applied', 'Reconciled')
              AND NEW.applied_at_ms IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'applied intent status requires timestamp');
            END;

            CREATE TRIGGER operation_intents_validate_status_update
            BEFORE UPDATE ON operation_intents
            WHEN
                (NEW.status IN ('Applied', 'Reconciled')
                    AND NEW.applied_at_ms IS NULL)
                OR NEW.operation_id <> OLD.operation_id
                OR NEW.sequence <> OLD.sequence
                OR NEW.kind <> OLD.kind
                OR NEW.idempotency_key <> OLD.idempotency_key
                OR NEW.recorded_at_ms <> OLD.recorded_at_ms
            BEGIN
                SELECT RAISE(ABORT, 'operation intent state or identity is invalid');
            END;

            DROP TRIGGER operations_require_success_evidence;
            CREATE TRIGGER operations_require_success_evidence
            BEFORE UPDATE OF status ON operations
            WHEN NEW.status = 'Succeeded' AND OLD.status <> 'Succeeded'
            BEGIN
                SELECT RAISE(ABORT, 'operation success requires verification evidence')
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM operation_evidence
                    WHERE operation_id = NEW.operation_id
                      AND kind = 'Verification'
                      AND outcome = 'Succeeded'
                );
                SELECT RAISE(ABORT, 'operation success requires cleanup evidence')
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM operation_evidence
                    WHERE operation_id = NEW.operation_id
                      AND kind = 'Cleanup'
                      AND outcome = 'Succeeded'
                );
            END;

            DELETE FROM schema_migrations WHERE version >= 4;
            PRAGMA user_version = 3;
            """;
        _ = command.ExecuteNonQuery();
    }

    private static void DowngradeFixtureToV4(string databasePath)
    {
        using var connection = OpenReadWrite(databasePath);
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            DROP TRIGGER operation_intents_validate_status_insert;
            DROP TRIGGER operation_intents_validate_status_update;

            CREATE TABLE operation_intents_v4 (
                operation_intent_id TEXT NOT NULL PRIMARY KEY
                    CHECK (length(operation_intent_id) = 36),
                operation_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                kind TEXT NOT NULL CHECK (kind IN (
                    'ChallengeWrite', 'CertificateDeploy', 'Activate', 'Rollback',
                    'RemotePrepare', 'RemoteVerify', 'Commit', 'Abort'
                )),
                idempotency_key TEXT NOT NULL UNIQUE
                    CHECK (length(idempotency_key) BETWEEN 1 AND 200),
                status TEXT NOT NULL CHECK (status IN (
                    'Planned', 'Applied', 'Reconciled', 'Failed', 'Uncertain'
                )),
                recorded_at_ms INTEGER NOT NULL,
                applied_at_ms INTEGER NULL,
                UNIQUE (operation_id, sequence),
                FOREIGN KEY (operation_id)
                    REFERENCES operations(operation_id) ON DELETE RESTRICT
            ) STRICT;

            INSERT INTO operation_intents_v4 (
                operation_intent_id,
                operation_id,
                sequence,
                kind,
                idempotency_key,
                status,
                recorded_at_ms,
                applied_at_ms
            )
            SELECT
                operation_intent_id,
                operation_id,
                sequence,
                kind,
                idempotency_key,
                status,
                recorded_at_ms,
                applied_at_ms
            FROM operation_intents;

            DROP TABLE operation_intents;
            ALTER TABLE operation_intents_v4 RENAME TO operation_intents;

            CREATE TRIGGER operation_intents_validate_status_insert
            BEFORE INSERT ON operation_intents
            WHEN NEW.status IN ('Applied', 'Reconciled')
              AND NEW.applied_at_ms IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'applied intent status requires timestamp');
            END;

            CREATE TRIGGER operation_intents_validate_status_update
            BEFORE UPDATE ON operation_intents
            WHEN
                (NEW.status IN ('Applied', 'Reconciled')
                    AND NEW.applied_at_ms IS NULL)
                OR NEW.operation_id <> OLD.operation_id
                OR NEW.sequence <> OLD.sequence
                OR NEW.kind <> OLD.kind
                OR NEW.idempotency_key <> OLD.idempotency_key
                OR NEW.recorded_at_ms <> OLD.recorded_at_ms
            BEGIN
                SELECT RAISE(ABORT, 'operation intent state or identity is invalid');
            END;

            DELETE FROM schema_migrations WHERE version = 5;
            PRAGMA user_version = 4;
            """;
        _ = command.ExecuteNonQuery();
    }

    private static string[] ReadMigrationMetadata(
        string databasePath,
        int throughVersion)
    {
        using var connection = OpenReadOnly(databasePath);
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT version, name, checksum_sha256, applied_at_ms
            FROM schema_migrations
            WHERE version <= $through_version
            ORDER BY version;
            """;
        command.Parameters.AddWithValue("$through_version", throughVersion);
        using var reader = command.ExecuteReader();
        var rows = new List<string>();
        while (reader.Read())
        {
            rows.Add(
                $"{reader.GetInt64(0)}|{reader.GetString(1)}|{reader.GetString(2)}|{reader.GetInt64(3)}");
        }

        return rows.ToArray();
    }

    private static object? ReadScalar(SqliteConnection connection, string commandText)
    {
        using var command = connection.CreateCommand();
        command.CommandText = commandText;
        return command.ExecuteScalar();
    }

    private static long ReadInt64(SqliteConnection connection, string commandText) =>
        Convert.ToInt64(ReadScalar(connection, commandText), CultureInfo.InvariantCulture);

    private sealed record TargetFixture(
        ConnectionProfile Connection,
        CertificateTarget Target);
}
