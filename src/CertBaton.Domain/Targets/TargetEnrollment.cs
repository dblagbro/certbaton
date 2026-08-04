using System.Globalization;
using CertBaton.Domain.Connections;
using CertBaton.Domain.Deployments;
using CertBaton.Domain.Scheduling;

namespace CertBaton.Domain.Targets;

public readonly record struct EnrollmentId
{
    public EnrollmentId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "An enrollment identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static EnrollmentId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public sealed record TargetEnrollment
{
    public TargetEnrollment(
        EnrollmentId id,
        ConnectionProfile connection,
        CertificateTarget target,
        DeploymentPlan deploymentPlan,
        RenewalPolicy renewalPolicy,
        TargetIssuanceProfile issuanceProfile,
        DateTimeOffset enrolledAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An enrollment identifier cannot be empty.",
                nameof(id));
        }

        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(deploymentPlan);
        ArgumentNullException.ThrowIfNull(renewalPolicy);
        ArgumentNullException.ThrowIfNull(issuanceProfile);
        if (target.ConnectionId != connection.Id)
        {
            throw new ArgumentException(
                "The target must reference the enrolled connection.",
                nameof(target));
        }

        if (deploymentPlan.TargetId != target.Id ||
            renewalPolicy.TargetId != target.Id ||
            issuanceProfile.TargetId != target.Id)
        {
            throw new ArgumentException(
                "Every enrollment component must reference the enrolled target.");
        }

        Id = id;
        Connection = connection;
        Target = target;
        DeploymentPlan = deploymentPlan;
        RenewalPolicy = renewalPolicy;
        IssuanceProfile = issuanceProfile;
        EnrolledAtUtc = enrolledAtUtc.ToUniversalTime();
    }

    public EnrollmentId Id { get; }

    public ConnectionProfile Connection { get; }

    public CertificateTarget Target { get; }

    public DeploymentPlan DeploymentPlan { get; }

    public RenewalPolicy RenewalPolicy { get; }

    public TargetIssuanceProfile IssuanceProfile { get; }

    public DateTimeOffset EnrolledAtUtc { get; }
}
