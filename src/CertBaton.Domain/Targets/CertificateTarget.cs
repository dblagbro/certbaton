using System.Collections.ObjectModel;
using System.Globalization;
using CertBaton.Domain.Connections;

namespace CertBaton.Domain.Targets;

public readonly record struct TargetId
{
    public TargetId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "A target identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static TargetId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public readonly record struct TargetDnsName
{
    public TargetDnsName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value.Any(char.IsControl) ||
            value.StartsWith("*.", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "A target name must be a non-wildcard DNS name without surrounding whitespace.",
                nameof(value));
        }

        string asciiName;
        try
        {
            asciiName = new IdnMapping().GetAscii(value.TrimEnd('.'));
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException(
                "A target name must be a valid DNS name.",
                nameof(value),
                exception);
        }

        if (asciiName.Length is < 1 or > 253 ||
            Uri.CheckHostName(asciiName) != UriHostNameType.Dns)
        {
            throw new ArgumentException(
                "A target name must be a valid DNS name.",
                nameof(value));
        }

        Value = asciiName.ToLowerInvariant();
    }

    public string Value { get; }

    public override string ToString() => Value;
}

public enum TargetLifecycleStatus
{
    Unconfigured = 0,
    Ready = 1,
    Disabled = 2,
}

public sealed record CertificateTarget
{
    public CertificateTarget(
        TargetId id,
        ConnectionId connectionId,
        string displayName,
        TargetDnsName primaryName,
        IEnumerable<TargetDnsName>? alternativeNames,
        TargetLifecycleStatus lifecycleStatus,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A target identifier cannot be empty.",
                nameof(id));
        }

        if (connectionId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A connection identifier cannot be empty.",
                nameof(connectionId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        if (displayName.Length > 100 ||
            !string.Equals(displayName, displayName.Trim(), StringComparison.Ordinal) ||
            displayName.Any(char.IsControl))
        {
            throw new ArgumentException(
                "A target display name is invalid.",
                nameof(displayName));
        }

        if (string.IsNullOrEmpty(primaryName.Value))
        {
            throw new ArgumentException(
                "A target primary DNS name is required.",
                nameof(primaryName));
        }

        if (!Enum.IsDefined(lifecycleStatus))
        {
            throw new ArgumentOutOfRangeException(
                nameof(lifecycleStatus),
                lifecycleStatus,
                "The target lifecycle status is invalid.");
        }

        var names = new List<TargetDnsName> { primaryName };
        var uniqueNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            primaryName.Value,
        };
        if (alternativeNames is not null)
        {
            foreach (var alternativeName in alternativeNames)
            {
                if (string.IsNullOrEmpty(alternativeName.Value))
                {
                    throw new ArgumentException(
                        "A target alternative DNS name cannot be empty.",
                        nameof(alternativeNames));
                }

                if (uniqueNames.Add(alternativeName.Value))
                {
                    names.Add(alternativeName);
                }
            }
        }

        if (names.Count > 100)
        {
            throw new ArgumentException(
                "A target cannot contain more than 100 DNS names.",
                nameof(alternativeNames));
        }

        Id = id;
        ConnectionId = connectionId;
        DisplayName = displayName;
        PrimaryName = primaryName;
        Names = new ReadOnlyCollection<TargetDnsName>(names);
        LifecycleStatus = lifecycleStatus;
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        UpdatedAtUtc = updatedAtUtc.ToUniversalTime();
        if (UpdatedAtUtc < CreatedAtUtc)
        {
            throw new ArgumentException(
                "The updated timestamp cannot precede the created timestamp.",
                nameof(updatedAtUtc));
        }
    }

    public TargetId Id { get; }

    public ConnectionId ConnectionId { get; }

    public string DisplayName { get; }

    public TargetDnsName PrimaryName { get; }

    public IReadOnlyList<TargetDnsName> Names { get; }

    public TargetLifecycleStatus LifecycleStatus { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; }
}
