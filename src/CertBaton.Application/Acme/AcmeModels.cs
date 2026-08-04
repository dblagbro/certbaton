using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace CertBaton.Application.Acme;

public enum AcmeResourceStatus
{
    Unknown = 0,
    Pending,
    Processing,
    Ready,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

public sealed class AcmeAccount : IDisposable
{
    private byte[]? accountKeyPem;

    public AcmeAccount(
        Uri directoryUri,
        Uri accountUri,
        ReadOnlySpan<byte> accountKeyPem)
    {
        ValidateAbsoluteHttpsUri(directoryUri, nameof(directoryUri));
        ValidateAbsoluteHttpsUri(accountUri, nameof(accountUri));
        if (accountKeyPem.IsEmpty)
        {
            throw new ArgumentException(
                "The ACME account key cannot be empty.",
                nameof(accountKeyPem));
        }

        DirectoryUri = directoryUri;
        AccountUri = accountUri;
        this.accountKeyPem = accountKeyPem.ToArray();
    }

    public Uri DirectoryUri { get; }

    public Uri AccountUri { get; }

    public byte[] ExportAccountKeyPem()
    {
        var key = Volatile.Read(ref accountKeyPem);
        ObjectDisposedException.ThrowIf(key is null, this);
        return key.ToArray();
    }

    public void Dispose()
    {
        var key = Interlocked.Exchange(ref accountKeyPem, null);
        if (key is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(key);
    }

    public override string ToString() =>
        $"ACME account {AccountUri} (key redacted)";

    internal static void ValidateAbsoluteHttpsUri(Uri uri, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(uri, parameterName);
        if (!uri.IsAbsoluteUri ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The ACME URI must be an absolute HTTPS URI.",
                parameterName);
        }
    }
}

public sealed record AcmeAccountRequest
{
    public AcmeAccountRequest(
        Uri directoryUri,
        IEnumerable<string>? contactUris,
        bool termsOfServiceAgreed,
        AcmeAccount? existingAccount = null)
    {
        AcmeAccount.ValidateAbsoluteHttpsUri(directoryUri, nameof(directoryUri));

        var contacts = (contactUris ?? [])
            .Select(static value => value?.Trim())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (var contact in contacts)
        {
            if (!Uri.TryCreate(contact, UriKind.Absolute, out _))
            {
                throw new ArgumentException(
                    "Every ACME contact must be an absolute URI.",
                    nameof(contactUris));
            }
        }

        if (existingAccount is not null && existingAccount.DirectoryUri != directoryUri)
        {
            throw new ArgumentException(
                "The existing account belongs to a different ACME directory.",
                nameof(existingAccount));
        }

        DirectoryUri = directoryUri;
        ContactUris = Array.AsReadOnly(contacts);
        TermsOfServiceAgreed = termsOfServiceAgreed;
        ExistingAccount = existingAccount;
    }

    public Uri DirectoryUri { get; }

    public IReadOnlyList<string> ContactUris { get; }

    public bool TermsOfServiceAgreed { get; }

    public AcmeAccount? ExistingAccount { get; }
}

public sealed record AcmeAccountResult(
    AcmeAccount Account,
    AcmeResourceStatus Status,
    bool Created);

public sealed record AcmeOrderRequest
{
    public AcmeOrderRequest(
        IEnumerable<string> dnsIdentifiers,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        string? replacesCertificateId = null,
        string? profile = null)
    {
        ArgumentNullException.ThrowIfNull(dnsIdentifiers);

        var identifiers = dnsIdentifiers
            .Select(static value => value?.Trim())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (identifiers.Length == 0)
        {
            throw new ArgumentException(
                "At least one DNS identifier is required.",
                nameof(dnsIdentifiers));
        }

        if (notBefore.HasValue && notAfter.HasValue && notAfter <= notBefore)
        {
            throw new ArgumentException(
                "The requested not-after time must be later than not-before.",
                nameof(notAfter));
        }

        DnsIdentifiers = Array.AsReadOnly(identifiers);
        NotBefore = notBefore;
        NotAfter = notAfter;
        ReplacesCertificateId = NormalizeOptional(replacesCertificateId);
        Profile = NormalizeOptional(profile);
    }

    public IReadOnlyList<string> DnsIdentifiers { get; }

    public DateTimeOffset? NotBefore { get; }

    public DateTimeOffset? NotAfter { get; }

    public string? ReplacesCertificateId { get; }

    public string? Profile { get; }

    private static string? NormalizeOptional(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public sealed record AcmeOrder(
    Uri OrderUri,
    IReadOnlyList<string> DnsIdentifiers,
    AcmeResourceStatus Status,
    DateTimeOffset? Expires,
    AcmeProblem? Problem);

public sealed record AcmeHttp01Challenge(
    string Identifier,
    bool IsWildcard,
    Uri AuthorizationUri,
    Uri ChallengeUri,
    string Token,
    string KeyAuthorization,
    AcmeResourceStatus Status,
    DateTimeOffset? Validated,
    AcmeProblem? Problem);

public sealed record AcmeChallenge(
    Uri ChallengeUri,
    AcmeResourceStatus Status,
    DateTimeOffset? Validated,
    AcmeProblem? Problem);

public sealed record AcmeChallengePollResult(
    AcmeChallenge Challenge,
    int Attempts,
    bool TimedOut);

public sealed record AcmeOrderPollResult(
    AcmeOrder Order,
    int Attempts,
    bool TimedOut);

public sealed record AcmePollingPolicy
{
    public static AcmePollingPolicy Default { get; } = new(30, TimeSpan.FromSeconds(2));

    public AcmePollingPolicy(int maxAttempts, TimeSpan interval)
    {
        if (maxAttempts is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxAttempts),
                maxAttempts,
                "ACME polling attempts must be between 1 and 100.");
        }

        if (interval < TimeSpan.Zero || interval > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(
                nameof(interval),
                interval,
                "The ACME polling interval must be between zero and five minutes.");
        }

        MaxAttempts = maxAttempts;
        Interval = interval;
    }

    public int MaxAttempts { get; }

    public TimeSpan Interval { get; }
}

public sealed record AcmeCertificateChain(
    string LeafCertificatePem,
    IReadOnlyList<string> IssuerCertificatesPem,
    string FullChainPem);

public sealed record AcmeProblem
{
    public AcmeProblem(
        string? type,
        string? detail,
        int? httpStatus,
        string? identifier,
        IEnumerable<AcmeProblem>? subproblems = null)
    {
        Type = type;
        Detail = detail;
        HttpStatus = httpStatus;
        Identifier = identifier;
        Subproblems = new ReadOnlyCollection<AcmeProblem>(
            (subproblems ?? []).ToArray());
    }

    public string? Type { get; }

    public string? Detail { get; }

    public int? HttpStatus { get; }

    public string? Identifier { get; }

    public IReadOnlyList<AcmeProblem> Subproblems { get; }
}
