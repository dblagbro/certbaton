using System.Security.Cryptography;
using System.Text;
using CertBaton.Application.Live;
using CertBaton.Application.Persistence;
using CertBaton.Domain.Operations;

namespace CertBaton.Service;

public sealed class ProductionLiveRenewalJournal : ILiveRenewalJournal
{
    private readonly IProductionStore store;
    private readonly OperationId operationId;
    private readonly Guid executionEpoch;

    public ProductionLiveRenewalJournal(
        IProductionStore store,
        OperationId operationId,
        Guid executionEpoch)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (executionEpoch == Guid.Empty)
        {
            throw new ArgumentException(
                "The execution epoch cannot be empty.",
                nameof(executionEpoch));
        }

        this.store = store;
        this.operationId = operationId;
        this.executionEpoch = executionEpoch;
    }

    public Task AppendAsync(
        LiveRenewalJournalEntry entry,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();
        if (entry.OperationId != operationId.Value)
        {
            throw new InvalidOperationException(
                "A live journal entry cannot cross operation boundaries.");
        }

        if (entry.Category == LiveRenewalJournalCategory.Intent)
        {
            if (TryMapIntentKind(entry.Action, out var intentKind))
            {
                PersistIntent(entry, intentKind);
            }

            return Task.CompletedTask;
        }

        if (TryMapIntentKind(entry.Action, out var appliedIntentKind))
        {
            PersistIntent(entry, appliedIntentKind);
        }

        ReconcileChallengeWrite(entry);

        var evidenceKind = MapEvidenceKind(entry);
        _ = store.AppendOperationEvidence(
            operationId,
            evidenceKind,
            evidenceKind == OperationEvidenceKind.Stage
                ? ToStage(entry.Action)
                : null,
            MapOutcome(entry.Outcome),
            entry.RecordedAtUtc,
            entry.Code,
            entry.Description);
        return Task.CompletedTask;
    }

    private void ReconcileChallengeWrite(LiveRenewalJournalEntry entry)
    {
        if (entry.Action != LiveRenewalJournalAction.ChallengeCleanup ||
            entry.Outcome != LiveRenewalJournalOutcome.Succeeded ||
            entry.Subject is null)
        {
            return;
        }

        var idempotencyKey = CreateIntentKey(
            entry.OperationId,
            LiveRenewalJournalAction.ChallengeWrite,
            entry.Subject);
        var existing = store.FindOperationIntentByIdempotencyKey(idempotencyKey);
        if (existing?.Status is not (
                OperationIntentStatus.Planned or
                OperationIntentStatus.Applied or
                OperationIntentStatus.Failed or
                OperationIntentStatus.Uncertain))
        {
            return;
        }

        _ = store.TransitionOwnedOperationIntentStatus(
            existing.Id,
            executionEpoch,
            existing.Status,
            OperationIntentStatus.Reconciled,
            entry.RecordedAtUtc);
    }

    private void PersistIntent(
        LiveRenewalJournalEntry entry,
        OperationIntentKind intentKind)
    {
        var idempotencyKey = CreateIntentKey(entry);
        if (entry.Category == LiveRenewalJournalCategory.Intent)
        {
            var plannedExisting = store.FindOperationIntentByIdempotencyKey(
                idempotencyKey);
            if (plannedExisting is not null)
            {
                if (plannedExisting.OperationId != operationId ||
                    plannedExisting.Kind != intentKind ||
                    !string.Equals(
                        plannedExisting.RemotePath,
                        GetRemotePath(entry, intentKind),
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "A durable remote intent conflicts with this renewal operation.");
                }

                return;
            }

            _ = store.CreateOrGetOperationIntent(
                new OperationIntent(
                    CreateStableIntentId(idempotencyKey),
                    operationId,
                    entry.Sequence,
                    intentKind,
                    idempotencyKey,
                    OperationIntentStatus.Planned,
                    entry.RecordedAtUtc,
                    remotePath: GetRemotePath(entry, intentKind)));
            return;
        }

        var existing = store.FindOperationIntentByIdempotencyKey(idempotencyKey)
            ?? throw new InvalidOperationException(
                "Applied remote evidence has no durable write-ahead intent.");
        var targetStatus = entry.Outcome switch
        {
            LiveRenewalJournalOutcome.Applied or
            LiveRenewalJournalOutcome.Succeeded =>
                OperationIntentStatus.Applied,
            LiveRenewalJournalOutcome.Failed => OperationIntentStatus.Failed,
            LiveRenewalJournalOutcome.Cancelled => OperationIntentStatus.Uncertain,
            _ => existing.Status,
        };
        if (targetStatus != existing.Status)
        {
            _ = store.TransitionOwnedOperationIntentStatus(
                existing.Id,
                executionEpoch,
                existing.Status,
                targetStatus,
                entry.RecordedAtUtc);
        }
    }

    private static string? GetRemotePath(
        LiveRenewalJournalEntry entry,
        OperationIntentKind intentKind) =>
        intentKind == OperationIntentKind.ChallengeWrite
            ? entry.Subject ?? throw new InvalidOperationException(
                "A challenge-write intent requires its exact remote path.")
            : null;

    private static bool TryMapIntentKind(
        LiveRenewalJournalAction action,
        out OperationIntentKind kind)
    {
        switch (action)
        {
            case LiveRenewalJournalAction.ChallengeWrite:
                kind = OperationIntentKind.ChallengeWrite;
                return true;
            case LiveRenewalJournalAction.CertificateDeployment:
                kind = OperationIntentKind.CertificateDeploy;
                return true;
            case LiveRenewalJournalAction.Activation:
                kind = OperationIntentKind.Activate;
                return true;
            case LiveRenewalJournalAction.RemotePrepare:
                kind = OperationIntentKind.RemotePrepare;
                return true;
            case LiveRenewalJournalAction.Rollback:
                kind = OperationIntentKind.Rollback;
                return true;
            case LiveRenewalJournalAction.Commit:
                kind = OperationIntentKind.Commit;
                return true;
            case LiveRenewalJournalAction.Abort:
                kind = OperationIntentKind.Abort;
                return true;
            default:
                kind = default;
                return false;
        }
    }

    private static OperationEvidenceKind MapEvidenceKind(
        LiveRenewalJournalEntry entry) =>
        entry.Action switch
        {
            LiveRenewalJournalAction.PublicTlsVerification =>
                OperationEvidenceKind.Verification,
            LiveRenewalJournalAction.ChallengeCleanup =>
                OperationEvidenceKind.Cleanup,
            LiveRenewalJournalAction.Terminal =>
                OperationEvidenceKind.Terminal,
            _ => OperationEvidenceKind.Stage,
        };

    private static OperationEvidenceOutcome MapOutcome(
        LiveRenewalJournalOutcome outcome) =>
        outcome switch
        {
            LiveRenewalJournalOutcome.Failed =>
                OperationEvidenceOutcome.Failed,
            LiveRenewalJournalOutcome.Cancelled =>
                OperationEvidenceOutcome.Cancelled,
            _ => OperationEvidenceOutcome.Succeeded,
        };

    private static string ToStage(LiveRenewalJournalAction action)
    {
        var name = action.ToString();
        var builder = new StringBuilder(name.Length + 8);
        for (var index = 0; index < name.Length; index++)
        {
            var character = name[index];
            if (index > 0 && char.IsUpper(character))
            {
                builder.Append('-');
            }

            builder.Append(char.ToLowerInvariant(character));
        }

        return builder.ToString();
    }

    private static string CreateIntentKey(LiveRenewalJournalEntry entry)
        => CreateIntentKey(entry.OperationId, entry.Action, entry.Subject);

    private static string CreateIntentKey(
        Guid operationId,
        LiveRenewalJournalAction action,
        string? subject)
    {
        var source = Encoding.UTF8.GetBytes(
            $"{operationId:D}|{action}|{subject ?? string.Empty}");
        var digest = SHA256.HashData(source);
        return $"live:{operationId:N}:{action}:{Convert.ToHexStringLower(digest.AsSpan(0, 12))}";
    }

    private static OperationIntentId CreateStableIntentId(string key)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        Span<byte> guidBytes = stackalloc byte[16];
        digest.AsSpan(0, guidBytes.Length).CopyTo(guidBytes);
        guidBytes[7] = (byte)((guidBytes[7] & 0x0F) | 0x80);
        guidBytes[8] = (byte)((guidBytes[8] & 0x3F) | 0x80);
        return new OperationIntentId(new Guid(guidBytes));
    }
}
