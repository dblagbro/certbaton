using System.Globalization;
using CertBaton.Domain.Targets;

namespace CertBaton.Domain.Deployments;

public readonly record struct DeploymentPlanId
{
    public DeploymentPlanId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "A deployment plan identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static DeploymentPlanId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public readonly record struct RemotePath
{
    public RemotePath(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 1_024 ||
            value[0] != '/' ||
            value.Contains('\\', StringComparison.Ordinal) ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException(
                "A remote path must be a bounded absolute POSIX path.",
                nameof(value));
        }

        var segments = value.Split('/', StringSplitOptions.None);
        if (segments.Skip(1).Any(
                segment => segment.Length is 0 or > 255 ||
                    segment is "." or ".."))
        {
            throw new ArgumentException(
                "A remote path cannot contain empty, dot, or oversized segments.",
                nameof(value));
        }

        Value = value;
    }

    public string Value { get; }

    public override string ToString() => Value;
}

public enum DeploymentKind
{
    Nginx = 0,
}

public sealed record DeploymentPlan
{
    public DeploymentPlan(
        DeploymentPlanId id,
        TargetId targetId,
        DeploymentKind kind,
        RemotePath challengeWebroot,
        RemotePath? remoteIncomingRoot,
        RemotePath certificatePath,
        RemotePath privateKeyPath,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc,
        bool enabled = true)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A deployment plan identifier cannot be empty.",
                nameof(id));
        }

        if (targetId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A target identifier cannot be empty.",
                nameof(targetId));
        }

        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(
                nameof(kind),
                kind,
                "The deployment kind is invalid.");
        }

        if (string.IsNullOrEmpty(challengeWebroot.Value) ||
            string.IsNullOrEmpty(certificatePath.Value) ||
            string.IsNullOrEmpty(privateKeyPath.Value))
        {
            throw new ArgumentException(
                "Deployment paths cannot be empty.");
        }

        if (enabled && !remoteIncomingRoot.HasValue)
        {
            throw new ArgumentException(
                "An enabled deployment plan requires a remote incoming root.",
                nameof(remoteIncomingRoot));
        }

        if (remoteIncomingRoot.HasValue &&
            string.IsNullOrEmpty(remoteIncomingRoot.Value.Value))
        {
            throw new ArgumentException(
                "A remote incoming root cannot be empty.",
                nameof(remoteIncomingRoot));
        }

        if (remoteIncomingRoot.HasValue &&
            (string.Equals(
                    remoteIncomingRoot.Value.Value,
                    challengeWebroot.Value,
                    StringComparison.Ordinal) ||
                remoteIncomingRoot.Value.Value.StartsWith(
                    challengeWebroot.Value + "/",
                    StringComparison.Ordinal)))
        {
            throw new ArgumentException(
                "The remote incoming root cannot be inside the public challenge webroot.",
                nameof(remoteIncomingRoot));
        }

        if (certificatePath == privateKeyPath)
        {
            throw new ArgumentException(
                "Certificate and private-key paths must be distinct.",
                nameof(privateKeyPath));
        }

        Id = id;
        TargetId = targetId;
        Kind = kind;
        ChallengeWebroot = challengeWebroot;
        RemoteIncomingRoot = remoteIncomingRoot;
        CertificatePath = certificatePath;
        PrivateKeyPath = privateKeyPath;
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        UpdatedAtUtc = updatedAtUtc.ToUniversalTime();
        if (UpdatedAtUtc < CreatedAtUtc)
        {
            throw new ArgumentException(
                "The updated timestamp cannot precede the created timestamp.",
                nameof(updatedAtUtc));
        }

        Enabled = enabled;
    }

    public DeploymentPlanId Id { get; }

    public TargetId TargetId { get; }

    public DeploymentKind Kind { get; }

    public RemotePath ChallengeWebroot { get; }

    public RemotePath? RemoteIncomingRoot { get; }

    public RemotePath CertificatePath { get; }

    public RemotePath PrivateKeyPath { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; }

    public bool Enabled { get; }
}
