using System.Globalization;

namespace CertBaton.Domain.Targets;

public readonly record struct AcmeAccountId
{
    public AcmeAccountId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "An ACME account identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static AcmeAccountId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public enum AcmeAccountStatus
{
    Pending = 0,
    Valid = 1,
    Deactivated = 2,
    Revoked = 3,
}

public sealed record AcmeAccountRecord
{
    public AcmeAccountRecord(
        AcmeAccountId id,
        Uri directoryUri,
        Uri? accountUri,
        string? contactEmail,
        string keySecretReference,
        AcmeAccountStatus status,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An ACME account identifier cannot be empty.",
                nameof(id));
        }

        DirectoryUri = ValidateHttpsUri(directoryUri, nameof(directoryUri));
        if (accountUri is not null)
        {
            accountUri = ValidateHttpsUri(accountUri, nameof(accountUri));
        }

        if (status == AcmeAccountStatus.Valid && accountUri is null)
        {
            throw new ArgumentException(
                "A valid ACME account requires its account URI.",
                nameof(accountUri));
        }

        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        if (contactEmail is not null &&
            (string.IsNullOrWhiteSpace(contactEmail) ||
                contactEmail.Length > 320 ||
                !string.Equals(contactEmail, contactEmail.Trim(), StringComparison.Ordinal) ||
                contactEmail.Any(char.IsControl)))
        {
            throw new ArgumentException(
                "The ACME contact email is invalid.",
                nameof(contactEmail));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(keySecretReference);
        if (keySecretReference.Length > 200 ||
            !string.Equals(
                keySecretReference,
                keySecretReference.Trim(),
                StringComparison.Ordinal) ||
            keySecretReference.Any(char.IsControl))
        {
            throw new ArgumentException(
                "The ACME account key secret reference is invalid.",
                nameof(keySecretReference));
        }

        Id = id;
        AccountUri = accountUri;
        ContactEmail = contactEmail;
        KeySecretReference = keySecretReference;
        Status = status;
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        UpdatedAtUtc = updatedAtUtc.ToUniversalTime();
        if (UpdatedAtUtc < CreatedAtUtc)
        {
            throw new ArgumentException(
                "The updated timestamp cannot precede the created timestamp.",
                nameof(updatedAtUtc));
        }
    }

    public AcmeAccountId Id { get; }

    public Uri DirectoryUri { get; }

    public Uri? AccountUri { get; }

    public string? ContactEmail { get; }

    public string KeySecretReference { get; }

    public AcmeAccountStatus Status { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; }

    private static Uri ValidateHttpsUri(Uri uri, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(uri, parameterName);
        if (!uri.IsAbsoluteUri ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            uri.AbsoluteUri.Length > 2_048 ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException(
                "An ACME URI must be an absolute HTTPS URI without user information or a fragment.",
                parameterName);
        }

        return uri;
    }
}
