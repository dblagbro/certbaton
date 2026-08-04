using System.Net.Mail;

namespace CertBaton.Domain.Targets;

public readonly record struct AcmeContactUri
{
    public AcmeContactUri(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value.Length > 320 ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException(
                "An ACME contact must be a bounded URI or email address.",
                nameof(value));
        }

        var candidate = value;
        if (!value.Contains(':', StringComparison.Ordinal))
        {
            try
            {
                var address = new MailAddress(value);
                if (!string.Equals(address.Address, value, StringComparison.OrdinalIgnoreCase))
                {
                    throw new FormatException("The email address contains a display name.");
                }
            }
            catch (FormatException exception)
            {
                throw new ArgumentException(
                    "An ACME contact email address is invalid.",
                    nameof(value),
                    exception);
            }

            candidate = $"mailto:{value}";
        }

        const string mailtoPrefix = "mailto:";
        if (!candidate.StartsWith(mailtoPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The supported ACME contact URI scheme is mailto.",
                nameof(value));
        }

        var email = candidate[mailtoPrefix.Length..];
        try
        {
            var address = new MailAddress(email);
            if (!string.Equals(address.Address, email, StringComparison.OrdinalIgnoreCase))
            {
                throw new FormatException("The contact contains a display name.");
            }

            var normalized = $"mailto:{address.Address}";
            if (normalized.Length > 320)
            {
                throw new FormatException("The contact URI is too long.");
            }

            Value = normalized;
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "The ACME mailto contact is invalid.",
                nameof(value),
                exception);
        }
    }

    public string Value { get; }

    public override string ToString() => Value;
}

public sealed record TargetIssuanceProfile
{
    public TargetIssuanceProfile(
        TargetId targetId,
        Uri directoryUri,
        AcmeContactUri contact,
        bool termsAccepted,
        DateTimeOffset? termsAcceptedAtUtc,
        string accountKeySecretReference,
        Uri? accountUri,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc)
    {
        if (targetId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A target identifier cannot be empty.",
                nameof(targetId));
        }

        DirectoryUri = ValidateHttpsUri(directoryUri, nameof(directoryUri));
        if (string.IsNullOrEmpty(contact.Value))
        {
            throw new ArgumentException(
                "An ACME contact is required.",
                nameof(contact));
        }

        if (termsAccepted != termsAcceptedAtUtc.HasValue)
        {
            throw new ArgumentException(
                "Terms acceptance and its timestamp must be recorded together.",
                nameof(termsAcceptedAtUtc));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(accountKeySecretReference);
        if (accountKeySecretReference.Length > 200 ||
            !string.Equals(
                accountKeySecretReference,
                accountKeySecretReference.Trim(),
                StringComparison.Ordinal) ||
            accountKeySecretReference.Any(char.IsControl))
        {
            throw new ArgumentException(
                "The account key secret reference is invalid.",
                nameof(accountKeySecretReference));
        }

        if (accountUri is not null)
        {
            accountUri = ValidateHttpsUri(accountUri, nameof(accountUri));
        }

        TargetId = targetId;
        Contact = contact;
        TermsAccepted = termsAccepted;
        TermsAcceptedAtUtc = termsAcceptedAtUtc?.ToUniversalTime();
        AccountKeySecretReference = accountKeySecretReference;
        AccountUri = accountUri;
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        UpdatedAtUtc = updatedAtUtc.ToUniversalTime();
        if (UpdatedAtUtc < CreatedAtUtc)
        {
            throw new ArgumentException(
                "The updated timestamp cannot precede the created timestamp.",
                nameof(updatedAtUtc));
        }
    }

    public TargetId TargetId { get; }

    public Uri DirectoryUri { get; }

    public AcmeContactUri Contact { get; }

    public bool TermsAccepted { get; }

    public DateTimeOffset? TermsAcceptedAtUtc { get; }

    public string AccountKeySecretReference { get; }

    public Uri? AccountUri { get; }

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
