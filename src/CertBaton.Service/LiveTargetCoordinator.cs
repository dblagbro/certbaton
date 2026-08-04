using CertBaton.Application.Persistence;
using CertBaton.Contracts;
using CertBaton.Domain.Connections;
using CertBaton.Domain.Deployments;
using CertBaton.Domain.Scheduling;
using CertBaton.Domain.Targets;

namespace CertBaton.Service;

public sealed class LiveTargetCoordinator : ILiveTargetCoordinator
{
    private readonly IProductionStore store;
    private readonly TimeProvider timeProvider;

    public LiveTargetCoordinator(
        IProductionStore store,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(timeProvider);
        this.store = store;
        this.timeProvider = timeProvider;
    }

    public TargetSnapshot Enroll(
        TargetEnrollmentPayload payload,
        string actorSid)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSid);
        if (!payload.TryValidate(out var validationError))
        {
            throw new ArgumentException(validationError, nameof(payload));
        }

        var now = timeProvider.GetUtcNow();
        var aggregateId = payload.EnrollmentId;
        var connectionId = new ConnectionId(aggregateId);
        var targetId = new TargetId(aggregateId);
        var rawHostKey = Convert.FromBase64String(
            payload.HostKeyBase64 ??
                throw new ArgumentException(
                    "A live target requires the raw SSH host key.",
                    nameof(payload)));
        var connection = new ConnectionProfile(
            connectionId,
            payload.DisplayName,
            new ConnectionEndpoint(payload.Host, payload.Port),
            payload.Username,
            payload.CredentialReference.ToString("D"),
            payload.HostKeyAlgorithm,
            payload.HostKeyFingerprintSha256,
            now,
            now,
            enabled: true,
            rawHostKey);
        var names = payload.DnsNames
            .Select(static name => new TargetDnsName(name))
            .ToArray();
        var target = new CertificateTarget(
            targetId,
            connectionId,
            payload.DisplayName,
            names[0],
            names.Skip(1),
            TargetLifecycleStatus.Ready,
            now,
            now);
        var deployment = new DeploymentPlan(
            new DeploymentPlanId(aggregateId),
            targetId,
            DeploymentKind.Nginx,
            new RemotePath(payload.ChallengeWebroot),
            new RemotePath(payload.IncomingRoot),
            new RemotePath(payload.CertificatePath),
            new RemotePath(payload.PrivateKeyPath),
            now,
            now,
            enabled: true);
        var policy = new RenewalPolicy(
            new RenewalPolicyId(aggregateId),
            targetId,
            payload.RenewBeforeDays,
            payload.CheckIntervalMinutes,
            payload.AutoRenew,
            payload.AutoRenew ? now : null,
            now,
            now);
        var issuance = new TargetIssuanceProfile(
            targetId,
            ResolveDirectory(payload.CertificateAuthority),
            new AcmeContactUri(payload.ContactEmail),
            payload.TermsOfServiceAgreed,
            now,
            aggregateId.ToString("D"),
            accountUri: null,
            now,
            now);
        store.SaveEnrollment(
            new TargetEnrollment(
                new EnrollmentId(aggregateId),
                connection,
                target,
                deployment,
                policy,
                issuance,
                now));

        return ToSnapshot(target, connection, policy, issuance);
    }

    public TargetListSnapshot List()
    {
        var targets = store.ListTargets(LiveContractValues.MaximumTargets);
        var snapshots = new List<TargetSnapshot>(targets.Count);
        foreach (var target in targets)
        {
            var connection = store.FindConnection(target.ConnectionId);
            if (connection is null)
            {
                throw new InvalidOperationException(
                    "A persisted target refers to a missing connection.");
            }

            var policy = store.FindEnabledRenewalPolicy(target.Id);
            var issuance = store.FindTargetIssuanceProfile(target.Id);
            snapshots.Add(ToSnapshot(target, connection, policy, issuance));
        }

        return new TargetListSnapshot(snapshots.AsReadOnly());
    }

    internal static string ToCertificateAuthority(Uri directoryUri)
    {
        ArgumentNullException.ThrowIfNull(directoryUri);
        return directoryUri.AbsoluteUri switch
        {
            LiveContractValues.LetsEncryptStagingDirectory =>
                LiveContractValues.LetsEncryptStaging,
            LiveContractValues.LetsEncryptProductionDirectory =>
                LiveContractValues.LetsEncryptProduction,
            _ => LiveContractValues.UnconfiguredCertificateAuthority,
        };
    }

    internal static Uri ResolveDirectory(string certificateAuthority) =>
        certificateAuthority switch
        {
            LiveContractValues.LetsEncryptStaging =>
                new Uri(
                    LiveContractValues.LetsEncryptStagingDirectory,
                    UriKind.Absolute),
            LiveContractValues.LetsEncryptProduction =>
                new Uri(
                    LiveContractValues.LetsEncryptProductionDirectory,
                    UriKind.Absolute),
            _ => throw new ArgumentException(
                "The certificate authority is not supported.",
                nameof(certificateAuthority)),
        };

    private static TargetSnapshot ToSnapshot(
        CertificateTarget target,
        ConnectionProfile connection,
        RenewalPolicy? policy,
        TargetIssuanceProfile? issuance)
    {
        var configured =
            target.LifecycleStatus != TargetLifecycleStatus.Unconfigured &&
            connection.Enabled &&
            connection.HostKeyAlgorithm is not null &&
            connection.HasRawHostKey &&
            issuance is not null &&
            issuance.TermsAccepted &&
            ToCertificateAuthority(issuance.DirectoryUri) !=
                LiveContractValues.UnconfiguredCertificateAuthority;
        var status = !configured
            ? "unconfigured"
            : target.LifecycleStatus == TargetLifecycleStatus.Disabled
                ? "disabled"
                : "ready";
        var authority = configured
            ? ToCertificateAuthority(issuance!.DirectoryUri)
            : LiveContractValues.UnconfiguredCertificateAuthority;
        return new TargetSnapshot(
            target.Id.Value,
            target.DisplayName,
            target.Names.Select(static name => name.Value).ToArray(),
            connection.Endpoint.Host,
            connection.Endpoint.Port,
            connection.Username,
            connection.HostKeyAlgorithm ?? "unenrolled",
            connection.HostKeyFingerprint,
            authority,
            policy?.Enabled == true,
            policy?.NextDueAtUtc,
            status);
    }
}
