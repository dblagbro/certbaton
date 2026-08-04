using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace CertBaton.Persistence.Sqlite;

internal static class SqliteSchema
{
    public const int ApplicationId = 0x4342544E;
    public const int CurrentVersion = 5;
    public const int BusyTimeoutMilliseconds = 5_000;

    private const string V1MigrationName = "0001_simulation_jobs";
    private const string V2MigrationName = "0002_production_foundation";
    private const string V3MigrationName = "0003_live_orchestration";
    private const string V4MigrationName = "0004_live_completion_and_remote_intents";
    private const string V5MigrationName = "0005_durable_challenge_paths";
    private const string V1SchemaSql =
        """
        CREATE TABLE schema_migrations (
            version INTEGER NOT NULL PRIMARY KEY CHECK (version > 0),
            name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
            checksum_sha256 TEXT NOT NULL CHECK (length(checksum_sha256) = 64),
            applied_at_ms INTEGER NOT NULL
        ) STRICT;

        CREATE TABLE jobs (
            job_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL UNIQUE CHECK (length(job_id) = 36),
            request_key TEXT NOT NULL UNIQUE
                CHECK (length(request_key) BETWEEN 1 AND 200),
            failure_stage_index INTEGER NULL
                CHECK (failure_stage_index BETWEEN 0 AND 7),
            status TEXT NOT NULL
                CHECK (status IN (
                    'Queued',
                    'Running',
                    'Succeeded',
                    'Failed',
                    'Cancelled',
                    'Interrupted'
                )),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            execution_epoch TEXT NULL CHECK (
                execution_epoch IS NULL OR length(execution_epoch) = 36
            ),
            claimed_at_ms INTEGER NULL,
            completed_at_ms INTEGER NULL,
            CHECK (
                (status = 'Queued'
                    AND execution_epoch IS NULL
                    AND claimed_at_ms IS NULL
                    AND completed_at_ms IS NULL)
                OR
                (status = 'Running'
                    AND execution_epoch IS NOT NULL
                    AND claimed_at_ms IS NOT NULL
                    AND completed_at_ms IS NULL)
                OR
                (status IN (
                        'Succeeded',
                        'Failed',
                        'Cancelled',
                        'Interrupted'
                    )
                    AND completed_at_ms IS NOT NULL)
            )
        ) STRICT;

        CREATE TABLE evidence (
            job_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            kind TEXT NOT NULL
                CHECK (kind IN ('Stage', 'Terminal', 'Recovery')),
            stage_index INTEGER NULL CHECK (stage_index BETWEEN 0 AND 7),
            stage_outcome TEXT NULL
                CHECK (stage_outcome IN ('Succeeded', 'Failed', 'Cancelled')),
            recorded_at_ms INTEGER NOT NULL,
            code TEXT NOT NULL CHECK (length(code) BETWEEN 1 AND 128),
            description TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 1024),
            PRIMARY KEY (job_id, sequence),
            FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE RESTRICT,
            CHECK (
                (kind = 'Stage'
                    AND stage_index IS NOT NULL
                    AND stage_outcome IS NOT NULL)
                OR
                (kind IN ('Terminal', 'Recovery')
                    AND stage_index IS NULL
                    AND stage_outcome IS NULL)
            )
        ) STRICT;

        CREATE UNIQUE INDEX ux_jobs_single_active
        ON jobs ((1))
        WHERE status IN ('Queued', 'Running');
        """;
    private const string V2SchemaSql =
        """
        CREATE TABLE connections (
            connection_id TEXT NOT NULL PRIMARY KEY CHECK (length(connection_id) = 36),
            display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
            host TEXT NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
            port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
            username TEXT NOT NULL CHECK (length(username) BETWEEN 1 AND 128),
            credential_reference TEXT NOT NULL
                CHECK (length(credential_reference) BETWEEN 1 AND 200),
            host_key_fingerprint TEXT NOT NULL
                CHECK (length(host_key_fingerprint) BETWEEN 16 AND 200),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
        ) STRICT;

        CREATE TABLE targets (
            target_id TEXT NOT NULL PRIMARY KEY CHECK (length(target_id) = 36),
            connection_id TEXT NOT NULL,
            display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
            lifecycle_status TEXT NOT NULL
                CHECK (lifecycle_status IN ('Unconfigured', 'Ready', 'Disabled')),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
            FOREIGN KEY (connection_id)
                REFERENCES connections(connection_id) ON DELETE RESTRICT
        ) STRICT;

        CREATE TABLE target_names (
            target_id TEXT NOT NULL,
            name_ascii TEXT NOT NULL COLLATE NOCASE
                CHECK (length(name_ascii) BETWEEN 1 AND 253),
            is_primary INTEGER NOT NULL CHECK (is_primary IN (0, 1)),
            PRIMARY KEY (target_id, name_ascii),
            UNIQUE (name_ascii),
            FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE CASCADE
        ) STRICT;

        CREATE UNIQUE INDEX ux_target_names_one_primary
        ON target_names (target_id)
        WHERE is_primary = 1;

        CREATE TABLE deployment_plans (
            deployment_plan_id TEXT NOT NULL PRIMARY KEY
                CHECK (length(deployment_plan_id) = 36),
            target_id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('Nginx')),
            challenge_webroot TEXT NOT NULL
                CHECK (length(challenge_webroot) BETWEEN 1 AND 1024),
            certificate_path TEXT NOT NULL
                CHECK (length(certificate_path) BETWEEN 1 AND 1024),
            private_key_path TEXT NOT NULL
                CHECK (length(private_key_path) BETWEEN 1 AND 1024),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
            UNIQUE (target_id, kind),
            FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT
        ) STRICT;

        CREATE TABLE operations (
            operation_id TEXT NOT NULL PRIMARY KEY CHECK (length(operation_id) = 36),
            target_id TEXT NOT NULL,
            request_key TEXT NOT NULL UNIQUE
                CHECK (length(request_key) BETWEEN 1 AND 200),
            kind TEXT NOT NULL CHECK (kind IN ('Renewal')),
            status TEXT NOT NULL CHECK (status IN (
                'Queued',
                'Running',
                'Blocked',
                'RollbackRequired',
                'Succeeded',
                'Failed',
                'Cancelled',
                'Interrupted'
            )),
            requested_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= requested_at_ms),
            started_at_ms INTEGER NULL,
            completed_at_ms INTEGER NULL,
            execution_epoch TEXT NULL
                CHECK (execution_epoch IS NULL OR length(execution_epoch) = 36),
            failure_code TEXT NULL
                CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128),
            FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT,
            CHECK (
                (status IN ('Queued', 'Running', 'Blocked', 'RollbackRequired')
                    AND completed_at_ms IS NULL)
                OR
                (status IN ('Succeeded', 'Failed', 'Cancelled', 'Interrupted')
                    AND completed_at_ms IS NOT NULL)
            )
        ) STRICT;

        CREATE UNIQUE INDEX ux_operations_one_active_per_target
        ON operations (target_id)
        WHERE status IN ('Queued', 'Running', 'Blocked', 'RollbackRequired');

        CREATE TABLE operation_evidence (
            operation_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            kind TEXT NOT NULL CHECK (kind IN (
                'Stage', 'Verification', 'Cleanup', 'Terminal', 'Recovery'
            )),
            stage TEXT NULL CHECK (stage IS NULL OR length(stage) BETWEEN 1 AND 64),
            outcome TEXT NOT NULL CHECK (outcome IN ('Succeeded', 'Failed', 'Cancelled')),
            recorded_at_ms INTEGER NOT NULL,
            code TEXT NOT NULL CHECK (length(code) BETWEEN 1 AND 128),
            description TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 1024),
            PRIMARY KEY (operation_id, sequence),
            FOREIGN KEY (operation_id)
                REFERENCES operations(operation_id) ON DELETE RESTRICT,
            CHECK (
                (kind = 'Stage' AND stage IS NOT NULL)
                OR (kind <> 'Stage' AND stage IS NULL)
            )
        ) STRICT;

        CREATE TABLE operation_intents (
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

        CREATE TABLE acme_accounts (
            acme_account_id TEXT NOT NULL PRIMARY KEY
                CHECK (length(acme_account_id) = 36),
            directory_uri TEXT NOT NULL CHECK (length(directory_uri) BETWEEN 8 AND 2048),
            account_uri TEXT NULL CHECK (account_uri IS NULL OR length(account_uri) BETWEEN 8 AND 2048),
            contact_email TEXT NULL CHECK (contact_email IS NULL OR length(contact_email) BETWEEN 3 AND 320),
            key_secret_reference TEXT NOT NULL
                CHECK (length(key_secret_reference) BETWEEN 1 AND 200),
            status TEXT NOT NULL CHECK (status IN ('Pending', 'Valid', 'Deactivated', 'Revoked')),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
            UNIQUE (directory_uri, key_secret_reference)
        ) STRICT;

        CREATE TABLE acme_orders (
            acme_order_id TEXT NOT NULL PRIMARY KEY CHECK (length(acme_order_id) = 36),
            operation_id TEXT NOT NULL UNIQUE,
            acme_account_id TEXT NOT NULL,
            order_uri TEXT NULL CHECK (order_uri IS NULL OR length(order_uri) BETWEEN 8 AND 2048),
            status TEXT NOT NULL CHECK (status IN (
                'Pending', 'Ready', 'Processing', 'Valid', 'Invalid'
            )),
            expires_at_ms INTEGER NULL,
            finalized_at_ms INTEGER NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
            FOREIGN KEY (operation_id)
                REFERENCES operations(operation_id) ON DELETE RESTRICT,
            FOREIGN KEY (acme_account_id)
                REFERENCES acme_accounts(acme_account_id) ON DELETE RESTRICT
        ) STRICT;

        CREATE TABLE certificate_artifacts (
            certificate_artifact_id TEXT NOT NULL PRIMARY KEY
                CHECK (length(certificate_artifact_id) = 36),
            operation_id TEXT NOT NULL UNIQUE,
            certificate_sha256 TEXT NOT NULL CHECK (length(certificate_sha256) = 64),
            public_key_sha256 TEXT NOT NULL CHECK (length(public_key_sha256) = 64),
            private_key_secret_reference TEXT NOT NULL
                CHECK (length(private_key_secret_reference) BETWEEN 1 AND 200),
            not_before_ms INTEGER NOT NULL,
            not_after_ms INTEGER NOT NULL CHECK (not_after_ms > not_before_ms),
            status TEXT NOT NULL CHECK (status IN ('Issued', 'Deployed', 'Revoked')),
            created_at_ms INTEGER NOT NULL,
            FOREIGN KEY (operation_id)
                REFERENCES operations(operation_id) ON DELETE RESTRICT
        ) STRICT;

        CREATE TABLE renewal_policies (
            renewal_policy_id TEXT NOT NULL PRIMARY KEY
                CHECK (length(renewal_policy_id) = 36),
            target_id TEXT NOT NULL UNIQUE,
            renew_before_days INTEGER NOT NULL CHECK (renew_before_days BETWEEN 1 AND 90),
            check_interval_minutes INTEGER NOT NULL
                CHECK (check_interval_minutes BETWEEN 15 AND 10080),
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
            next_due_at_ms INTEGER NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
            FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT
        ) STRICT;

        CREATE TABLE tls_probe_evidence (
            tls_probe_evidence_id TEXT NOT NULL PRIMARY KEY
                CHECK (length(tls_probe_evidence_id) = 36),
            operation_id TEXT NOT NULL,
            observed_at_ms INTEGER NOT NULL,
            host TEXT NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
            port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
            leaf_certificate_sha256 TEXT NOT NULL
                CHECK (length(leaf_certificate_sha256) = 64),
            chain_valid INTEGER NOT NULL CHECK (chain_valid IN (0, 1)),
            name_matches INTEGER NOT NULL CHECK (name_matches IN (0, 1)),
            expected_certificate_matches INTEGER NOT NULL
                CHECK (expected_certificate_matches IN (0, 1)),
            resolved_addresses TEXT NOT NULL
                CHECK (length(resolved_addresses) BETWEEN 2 AND 4096),
            FOREIGN KEY (operation_id)
                REFERENCES operations(operation_id) ON DELETE RESTRICT
        ) STRICT;

        CREATE TABLE audit_events (
            event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_event_id TEXT NOT NULL UNIQUE CHECK (length(audit_event_id) = 36),
            operation_id TEXT NULL,
            target_id TEXT NULL,
            actor_sid TEXT NULL CHECK (actor_sid IS NULL OR length(actor_sid) BETWEEN 5 AND 184),
            event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 100),
            occurred_at_ms INTEGER NOT NULL,
            code TEXT NOT NULL CHECK (length(code) BETWEEN 1 AND 128),
            description TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 1024),
            FOREIGN KEY (operation_id)
                REFERENCES operations(operation_id) ON DELETE RESTRICT,
            FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT
        ) STRICT;

        CREATE TRIGGER operations_reject_inserted_success
        BEFORE INSERT ON operations
        WHEN NEW.status = 'Succeeded'
        BEGIN
            SELECT RAISE(ABORT, 'operation success requires durable evidence');
        END;

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

        CREATE TRIGGER operation_evidence_preserve_success_delete
        BEFORE DELETE ON operation_evidence
        WHEN OLD.kind IN ('Verification', 'Cleanup')
          AND OLD.outcome = 'Succeeded'
          AND EXISTS (
              SELECT 1 FROM operations
              WHERE operation_id = OLD.operation_id
                AND status = 'Succeeded'
          )
        BEGIN
            SELECT RAISE(ABORT, 'successful operation evidence is immutable');
        END;

        CREATE TRIGGER operation_evidence_preserve_success_update
        BEFORE UPDATE ON operation_evidence
        WHEN OLD.kind IN ('Verification', 'Cleanup')
          AND OLD.outcome = 'Succeeded'
          AND EXISTS (
              SELECT 1 FROM operations
              WHERE operation_id = OLD.operation_id
                AND status = 'Succeeded'
          )
        BEGIN
            SELECT RAISE(ABORT, 'successful operation evidence is immutable');
        END;
        """;
    private const string V3SchemaSql =
        """
        ALTER TABLE connections
        ADD COLUMN host_key_algorithm TEXT NULL
            CHECK (
                host_key_algorithm IS NULL
                OR host_key_algorithm IN (
                    'ssh-ed25519',
                    'ecdsa-sha2-nistp256',
                    'ecdsa-sha2-nistp384',
                    'ecdsa-sha2-nistp521',
                    'rsa-sha2-256',
                    'rsa-sha2-512'
                )
            );

        ALTER TABLE connections
        ADD COLUMN raw_host_key BLOB NULL
            CHECK (
                raw_host_key IS NULL
                OR (
                    typeof(raw_host_key) = 'blob'
                    AND length(raw_host_key) BETWEEN 1 AND 65536
                )
            );

        UPDATE connections
        SET enabled = 0
        WHERE host_key_algorithm IS NULL;

        ALTER TABLE deployment_plans
        ADD COLUMN remote_incoming_root TEXT NULL
            CHECK (
                remote_incoming_root IS NULL
                OR length(remote_incoming_root) BETWEEN 1 AND 1024
            );

        UPDATE deployment_plans
        SET enabled = 0
        WHERE remote_incoming_root IS NULL;

        CREATE TABLE target_issuance_profiles (
            target_id TEXT NOT NULL PRIMARY KEY CHECK (length(target_id) = 36),
            directory_uri TEXT NOT NULL
                CHECK (
                    length(directory_uri) BETWEEN 8 AND 2048
                    AND lower(substr(directory_uri, 1, 8)) = 'https://'
                ),
            contact_uri TEXT NOT NULL
                CHECK (length(contact_uri) BETWEEN 3 AND 320),
            terms_accepted INTEGER NOT NULL CHECK (terms_accepted IN (0, 1)),
            terms_accepted_at_ms INTEGER NULL,
            account_key_secret_reference TEXT NOT NULL
                CHECK (length(account_key_secret_reference) BETWEEN 1 AND 200),
            account_uri TEXT NULL CHECK (
                account_uri IS NULL
                OR (
                    length(account_uri) BETWEEN 8 AND 2048
                    AND lower(substr(account_uri, 1, 8)) = 'https://'
                )
            ),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
            FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT,
            CHECK (
                (terms_accepted = 0 AND terms_accepted_at_ms IS NULL)
                OR (terms_accepted = 1 AND terms_accepted_at_ms IS NOT NULL)
            )
        ) STRICT;

        CREATE TABLE enrollments (
            enrollment_id TEXT NOT NULL PRIMARY KEY CHECK (length(enrollment_id) = 36),
            target_id TEXT NOT NULL UNIQUE CHECK (length(target_id) = 36),
            connection_id TEXT NOT NULL CHECK (length(connection_id) = 36),
            deployment_plan_id TEXT NOT NULL UNIQUE
                CHECK (length(deployment_plan_id) = 36),
            renewal_policy_id TEXT NOT NULL UNIQUE
                CHECK (length(renewal_policy_id) = 36),
            identity_sha256 TEXT NOT NULL CHECK (length(identity_sha256) = 64),
            enrolled_at_ms INTEGER NOT NULL,
            FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT,
            FOREIGN KEY (target_id)
                REFERENCES target_issuance_profiles(target_id) ON DELETE RESTRICT,
            FOREIGN KEY (connection_id)
                REFERENCES connections(connection_id) ON DELETE RESTRICT,
            FOREIGN KEY (deployment_plan_id)
                REFERENCES deployment_plans(deployment_plan_id) ON DELETE RESTRICT,
            FOREIGN KEY (renewal_policy_id)
                REFERENCES renewal_policies(renewal_policy_id) ON DELETE RESTRICT
        ) STRICT;

        CREATE TRIGGER connections_require_host_key_algorithm_insert
        BEFORE INSERT ON connections
        WHEN
            (NEW.enabled = 1 AND NEW.host_key_algorithm IS NULL)
            OR (NEW.raw_host_key IS NOT NULL AND NEW.host_key_algorithm IS NULL)
        BEGIN
            SELECT RAISE(ABORT, 'connection requires enrolled host-key algorithm');
        END;

        CREATE TRIGGER connections_require_host_key_algorithm_update
        BEFORE UPDATE ON connections
        WHEN
            (NEW.enabled = 1 AND NEW.host_key_algorithm IS NULL)
            OR (NEW.raw_host_key IS NOT NULL AND NEW.host_key_algorithm IS NULL)
        BEGIN
            SELECT RAISE(ABORT, 'connection requires enrolled host-key algorithm');
        END;

        CREATE TRIGGER deployment_plans_require_incoming_root_insert
        BEFORE INSERT ON deployment_plans
        WHEN NEW.enabled = 1 AND NEW.remote_incoming_root IS NULL
        BEGIN
            SELECT RAISE(ABORT, 'enabled deployment plan requires incoming root');
        END;

        CREATE TRIGGER deployment_plans_require_incoming_root_update
        BEFORE UPDATE ON deployment_plans
        WHEN NEW.enabled = 1 AND NEW.remote_incoming_root IS NULL
        BEGIN
            SELECT RAISE(ABORT, 'enabled deployment plan requires incoming root');
        END;

        CREATE UNIQUE INDEX ux_deployment_plans_one_enabled_per_target
        ON deployment_plans (target_id)
        WHERE enabled = 1;

        CREATE INDEX ix_acme_accounts_valid_directory
        ON acme_accounts (directory_uri, updated_at_ms DESC)
        WHERE status = 'Valid' AND account_uri IS NOT NULL;

        CREATE TRIGGER operations_validate_ownership_insert
        BEFORE INSERT ON operations
        WHEN
            (NEW.status = 'Queued'
                AND (NEW.started_at_ms IS NOT NULL OR NEW.execution_epoch IS NOT NULL))
            OR
            (NEW.status IN ('Running', 'Blocked', 'RollbackRequired')
                AND (NEW.started_at_ms IS NULL OR NEW.execution_epoch IS NULL))
            OR
            (NEW.started_at_ms IS NOT NULL
                AND NEW.started_at_ms < NEW.requested_at_ms)
            OR
            (NEW.started_at_ms IS NOT NULL
                AND NEW.updated_at_ms < NEW.started_at_ms)
            OR
            (NEW.completed_at_ms IS NOT NULL
                AND NEW.completed_at_ms < NEW.requested_at_ms)
            OR
            (NEW.started_at_ms IS NOT NULL
                AND NEW.completed_at_ms IS NOT NULL
                AND NEW.completed_at_ms < NEW.started_at_ms)
        BEGIN
            SELECT RAISE(ABORT, 'operation ownership or timestamps are invalid');
        END;

        CREATE TRIGGER operations_validate_ownership_update
        BEFORE UPDATE ON operations
        WHEN
            (NEW.status = 'Queued'
                AND (NEW.started_at_ms IS NOT NULL OR NEW.execution_epoch IS NOT NULL))
            OR
            (NEW.status IN ('Running', 'Blocked', 'RollbackRequired')
                AND (NEW.started_at_ms IS NULL OR NEW.execution_epoch IS NULL))
            OR
            (NEW.started_at_ms IS NOT NULL
                AND NEW.started_at_ms < NEW.requested_at_ms)
            OR
            (NEW.started_at_ms IS NOT NULL
                AND NEW.updated_at_ms < NEW.started_at_ms)
            OR
            (NEW.completed_at_ms IS NOT NULL
                AND NEW.completed_at_ms < NEW.requested_at_ms)
            OR
            (NEW.started_at_ms IS NOT NULL
                AND NEW.completed_at_ms IS NOT NULL
                AND NEW.completed_at_ms < NEW.started_at_ms)
            OR
            (OLD.execution_epoch IS NOT NULL
                AND NEW.execution_epoch IS NOT OLD.execution_epoch)
            OR
            (OLD.started_at_ms IS NOT NULL
                AND NEW.started_at_ms IS NOT OLD.started_at_ms)
        BEGIN
            SELECT RAISE(ABORT, 'operation ownership or timestamps are invalid');
        END;

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
        """;
    private const string V4SchemaSql =
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

        DROP TRIGGER operations_require_success_evidence;

        CREATE TRIGGER operations_require_success_evidence
        BEFORE UPDATE OF status ON operations
        WHEN NEW.status = 'Succeeded' AND OLD.status <> 'Succeeded'
        BEGIN
            SELECT RAISE(ABORT, 'operation success requires aggregate verification evidence')
            WHERE NOT EXISTS (
                SELECT 1
                FROM operation_evidence
                WHERE operation_id = NEW.operation_id
                  AND kind = 'Verification'
                  AND outcome = 'Succeeded'
                  AND code = 'tls.all_names_verified'
            );
            SELECT RAISE(ABORT, 'operation success requires aggregate cleanup evidence')
            WHERE NOT EXISTS (
                SELECT 1
                FROM operation_evidence
                WHERE operation_id = NEW.operation_id
                  AND kind = 'Cleanup'
                  AND outcome = 'Succeeded'
                  AND code = 'challenge.cleanup_complete'
            );
        END;
        """;
    private const string V5SchemaSql =
        """
        ALTER TABLE operation_intents
        ADD COLUMN remote_path TEXT NULL
            CHECK (
                remote_path IS NULL
                OR (
                    kind = 'ChallengeWrite'
                    AND length(remote_path) BETWEEN 2 AND 1024
                    AND substr(remote_path, 1, 1) = '/'
                    AND substr(remote_path, -1, 1) <> '/'
                )
            );

        DROP TRIGGER operation_intents_validate_status_insert;
        DROP TRIGGER operation_intents_validate_status_update;

        CREATE TRIGGER operation_intents_validate_status_insert
        BEFORE INSERT ON operation_intents
        WHEN
            (NEW.status IN ('Applied', 'Reconciled')
                AND NEW.applied_at_ms IS NULL)
            OR (NEW.kind = 'ChallengeWrite' AND NEW.remote_path IS NULL)
            OR (NEW.kind <> 'ChallengeWrite' AND NEW.remote_path IS NOT NULL)
        BEGIN
            SELECT RAISE(ABORT, 'operation intent state or remote path is invalid');
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
            OR NEW.remote_path IS NOT OLD.remote_path
        BEGIN
            SELECT RAISE(ABORT, 'operation intent state or identity is invalid');
        END;
        """;
    private static readonly string v1Checksum = ComputeChecksum(V1SchemaSql);
    private static readonly string v2Checksum = ComputeChecksum(V2SchemaSql);
    private static readonly string v3Checksum = ComputeChecksum(V3SchemaSql);
    private static readonly string v4Checksum = ComputeChecksum(V4SchemaSql);
    private static readonly string v5Checksum = ComputeChecksum(V5SchemaSql);

    public static void EnsureCurrent(
        SqliteConnection connection,
        DateTimeOffset initializedAtUtc)
    {
        var applicationId = ReadPragmaInteger(connection, "PRAGMA application_id;");
        if (applicationId == 0)
        {
            if (CountApplicationSchemaObjects(connection) != 0)
            {
                throw new InvalidOperationException(
                    "The database has content but no CertBaton application identifier.");
            }

            ApplyMigration(
                connection,
                1,
                V1MigrationName,
                v1Checksum,
                V1SchemaSql,
                initializedAtUtc);
        }
        else if (applicationId != ApplicationId)
        {
            throw new InvalidOperationException(
                "The database does not belong to CertBaton.");
        }

        var version = ReadPragmaInteger(connection, "PRAGMA user_version;");
        if (version < 1 || version > CurrentVersion)
        {
            throw new NotSupportedException(
                "The CertBaton database schema version is not supported.");
        }

        ValidateMigration(connection, 1, V1MigrationName, v1Checksum);
        if (version >= 2)
        {
            ValidateMigration(connection, 2, V2MigrationName, v2Checksum);
        }

        if (version >= 3)
        {
            ValidateMigration(connection, 3, V3MigrationName, v3Checksum);
        }

        if (version >= 4)
        {
            ValidateMigration(connection, 4, V4MigrationName, v4Checksum);
        }

        if (version >= 5)
        {
            ValidateMigration(connection, 5, V5MigrationName, v5Checksum);
        }

        ValidateStrictTables(connection, ["schema_migrations", "jobs", "evidence"]);
        if (version == 1)
        {
            ApplyMigration(
                connection,
                2,
                V2MigrationName,
                v2Checksum,
                V2SchemaSql,
                initializedAtUtc);
            version = 2;
        }

        if (version == 2)
        {
            ApplyMigration(
                connection,
                3,
                V3MigrationName,
                v3Checksum,
                V3SchemaSql,
                initializedAtUtc);
            version = 3;
        }

        if (version == 3)
        {
            ApplyMigration(
                connection,
                4,
                V4MigrationName,
                v4Checksum,
                V4SchemaSql,
                initializedAtUtc);
            version = 4;
        }

        if (version == 4)
        {
            ApplyMigration(
                connection,
                5,
                V5MigrationName,
                v5Checksum,
                V5SchemaSql,
                initializedAtUtc);
        }

        ValidateCurrentSchema(connection);
    }

    private static void ApplyMigration(
        SqliteConnection connection,
        int version,
        string name,
        string checksum,
        string schemaSql,
        DateTimeOffset appliedAtUtc)
    {
        using var transaction = connection.BeginTransaction(deferred: false);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = schemaSql;
            _ = command.ExecuteNonQuery();
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO schema_migrations (
                    version,
                    name,
                    checksum_sha256,
                    applied_at_ms
                )
                VALUES (
                    $version,
                    $name,
                    $checksum_sha256,
                    $applied_at_ms
                );
                """;
            command.Parameters.AddWithValue("$version", version);
            command.Parameters.AddWithValue("$name", name);
            command.Parameters.AddWithValue("$checksum_sha256", checksum);
            command.Parameters.AddWithValue(
                "$applied_at_ms",
                appliedAtUtc.ToUniversalTime().ToUnixTimeMilliseconds());
            _ = command.ExecuteNonQuery();
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                $"""
                PRAGMA application_id = {ApplicationId};
                PRAGMA user_version = {version};
                """;
            _ = command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    private static void ValidateCurrentSchema(SqliteConnection connection)
    {
        if (ReadPragmaInteger(connection, "PRAGMA application_id;") != ApplicationId)
        {
            throw new InvalidOperationException(
                "The CertBaton database application identifier is invalid.");
        }

        if (ReadPragmaInteger(connection, "PRAGMA user_version;") != CurrentVersion)
        {
            throw new NotSupportedException(
                "The CertBaton database schema version is not supported.");
        }

        ValidateMigration(connection, 1, V1MigrationName, v1Checksum);
        ValidateMigration(connection, 2, V2MigrationName, v2Checksum);
        ValidateMigration(connection, 3, V3MigrationName, v3Checksum);
        ValidateMigration(connection, 4, V4MigrationName, v4Checksum);
        ValidateMigration(connection, 5, V5MigrationName, v5Checksum);
        ValidateStrictTables(
            connection,
            [
                "schema_migrations",
                "jobs",
                "evidence",
                "connections",
                "targets",
                "target_names",
                "deployment_plans",
                "operations",
                "operation_evidence",
                "operation_intents",
                "acme_accounts",
                "acme_orders",
                "certificate_artifacts",
                "renewal_policies",
                "tls_probe_evidence",
                "audit_events",
                "target_issuance_profiles",
                "enrollments",
            ]);
    }

    private static void ValidateMigration(
        SqliteConnection connection,
        int version,
        string expectedName,
        string expectedChecksum)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT name, checksum_sha256
            FROM schema_migrations
            WHERE version = $version;
            """;
        command.Parameters.AddWithValue("$version", version);
        using var reader = command.ExecuteReader();
        if (!reader.Read() ||
            !string.Equals(reader.GetString(0), expectedName, StringComparison.Ordinal) ||
            !string.Equals(reader.GetString(1), expectedChecksum, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The CertBaton database migration metadata is invalid.");
        }
    }

    private static void ValidateStrictTables(
        SqliteConnection connection,
        IReadOnlyCollection<string> expectedTables)
    {
        using var command = connection.CreateCommand();
        var parameterNames = new List<string>(expectedTables.Count);
        var index = 0;
        foreach (var table in expectedTables)
        {
            var parameterName = $"$table_{index}";
            parameterNames.Add(parameterName);
            command.Parameters.AddWithValue(parameterName, table);
            index++;
        }

        command.CommandText =
            $"""
            SELECT COUNT(*)
            FROM pragma_table_list
            WHERE schema = 'main'
              AND name IN ({string.Join(", ", parameterNames)})
              AND strict = 1;
            """;
        var actual = Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
        if (actual != expectedTables.Count)
        {
            throw new InvalidOperationException(
                "The CertBaton database is missing a required STRICT table.");
        }
    }

    private static long ReadPragmaInteger(
        SqliteConnection connection,
        string commandText)
    {
        using var command = connection.CreateCommand();
        command.CommandText = commandText;
        return Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
    }

    private static long CountApplicationSchemaObjects(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT COUNT(*)
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%';
            """;
        return Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
    }

    private static string ComputeChecksum(string sql) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sql)));
}
