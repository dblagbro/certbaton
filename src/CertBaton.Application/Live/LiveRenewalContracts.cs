using System.Globalization;
using System.Net;
using CertBaton.Application.Acme;
using CertBaton.Application.Remote;
using CertBaton.Application.Security;
using CertBaton.Application.Verification;

namespace CertBaton.Application.Live;

public enum AcmeCertificateTrustMode
{
    PubliclyTrusted = 0,
    UntrustedTest = 1,
}

public enum LiveRenewalStatus
{
    Succeeded = 0,
    Failed = 1,
    Cancelled = 2,
    RollbackRequired = 3,
    Blocked = 4,
}

public enum LiveRenewalJournalCategory
{
    Intent = 0,
    Evidence = 1,
}

public enum LiveRenewalJournalAction
{
    Account = 0,
    Order = 1,
    ChallengeWrite = 2,
    ChallengeVerification = 3,
    ChallengeAcknowledgement = 4,
    ChallengeCleanup = 5,
    CertificateKeyPersistence = 6,
    CertificateFinalization = 7,
    CertificateInspection = 8,
    RemotePrepare = 9,
    CertificateDeployment = 10,
    Activation = 11,
    RemoteVerification = 12,
    PublicTlsVerification = 13,
    Commit = 14,
    Abort = 15,
    Rollback = 16,
    Terminal = 17,
    CertificateArtifactPersistence = 18,
}

public enum LiveRenewalJournalOutcome
{
    Planned = 0,
    Applied = 1,
    Succeeded = 2,
    Failed = 3,
    Cancelled = 4,
}

public sealed record LiveRenewalJournalEntry
{
    public LiveRenewalJournalEntry(
        Guid operationId,
        long sequence,
        LiveRenewalJournalCategory category,
        LiveRenewalJournalAction action,
        LiveRenewalJournalOutcome outcome,
        DateTimeOffset recordedAtUtc,
        string code,
        string description,
        string? subject = null)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "The operation identifier cannot be empty.",
                nameof(operationId));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        if (!Enum.IsDefined(category))
        {
            throw new ArgumentOutOfRangeException(nameof(category));
        }

        if (!Enum.IsDefined(action))
        {
            throw new ArgumentOutOfRangeException(nameof(action));
        }

        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome));
        }

        OperationId = operationId;
        Sequence = sequence;
        Category = category;
        Action = action;
        Outcome = outcome;
        RecordedAtUtc = recordedAtUtc.ToUniversalTime();
        Code = ValidateText(code, 128, nameof(code));
        Description = ValidateText(description, 512, nameof(description));
        Subject = subject is null
            ? null
            : ValidateText(subject, 1_024, nameof(subject));
    }

    public Guid OperationId { get; }

    public long Sequence { get; }

    public LiveRenewalJournalCategory Category { get; }

    public LiveRenewalJournalAction Action { get; }

    public LiveRenewalJournalOutcome Outcome { get; }

    public DateTimeOffset RecordedAtUtc { get; }

    public string Code { get; }

    public string Description { get; }

    public string? Subject { get; }

    private static string ValidateText(
        string value,
        int maximumLength,
        string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > maximumLength ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException(
                "Journal text must be bounded and contain no control characters.",
                parameterName);
        }

        return value;
    }
}

public interface ILiveRenewalJournal
{
    /// <summary>
    /// Durably appends one entry before this method completes.
    /// </summary>
    Task AppendAsync(
        LiveRenewalJournalEntry entry,
        CancellationToken cancellationToken);
}

public interface IAcmeAccountStore
{
    /// <summary>
    /// Returns the caller-owned account snapshot bound to the stable key
    /// reference, or <see langword="null"/>.
    /// </summary>
    Task<AcmeAccount?> LoadAsync(
        Uri directoryUri,
        SecretReference accountKeyReference,
        CancellationToken cancellationToken);

    /// <summary>
    /// Durably snapshots the account using the supplied stable protected-key
    /// reference before completing.
    /// </summary>
    Task SaveAsync(
        AcmeAccount account,
        SecretReference accountKeyReference,
        CancellationToken cancellationToken);
}

public interface ICertificatePrivateKeyStore
{
    /// <summary>
    /// Durably protects a pending private key before the ACME order is finalized.
    /// The implementation must not retain the supplied memory after this method completes.
    /// </summary>
    Task<SecretReference> StorePendingAsync(
        Guid operationId,
        ReadOnlyMemory<byte> privateKeyPem,
        CancellationToken cancellationToken);
}

public interface IIssuedCertificateStore
{
    /// <summary>
    /// Durably and idempotently records an issued certificate before any
    /// remote deployment is attempted.
    /// </summary>
    Task PersistIssuedAsync(
        LiveIssuedCertificateArtifact certificateArtifact,
        CancellationToken cancellationToken);
}

public sealed record LiveIssuedCertificateArtifact
{
    public LiveIssuedCertificateArtifact(
        Guid operationId,
        string certificateLeafSha256,
        string publicKeySha256,
        SecretReference privateKeyReference,
        DateTimeOffset notBeforeUtc,
        DateTimeOffset notAfterUtc)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "The operation identifier cannot be empty.",
                nameof(operationId));
        }

        if (privateKeyReference.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "The private-key reference cannot be empty.",
                nameof(privateKeyReference));
        }

        OperationId = operationId;
        CertificateLeafSha256 = ValidateSha256(
            certificateLeafSha256,
            nameof(certificateLeafSha256));
        PublicKeySha256 = ValidateSha256(
            publicKeySha256,
            nameof(publicKeySha256));
        PrivateKeyReference = privateKeyReference;
        NotBeforeUtc = notBeforeUtc.ToUniversalTime();
        NotAfterUtc = notAfterUtc.ToUniversalTime();
        if (NotAfterUtc <= NotBeforeUtc)
        {
            throw new ArgumentException(
                "The certificate not-after timestamp must follow not-before.",
                nameof(notAfterUtc));
        }
    }

    public Guid OperationId { get; }

    public string CertificateLeafSha256 { get; }

    /// <summary>
    /// Gets the SHA-256 digest of the DER SubjectPublicKeyInfo value.
    /// </summary>
    public string PublicKeySha256 { get; }

    public SecretReference PrivateKeyReference { get; }

    public DateTimeOffset NotBeforeUtc { get; }

    public DateTimeOffset NotAfterUtc { get; }

    private static string ValidateSha256(
        string value,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        var normalized = value
            .Replace(":", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();
        if (normalized.Length != 64 ||
            normalized.Any(
                static character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException(
                "A SHA-256 digest must contain exactly 64 hexadecimal characters.",
                parameterName);
        }

        return normalized;
    }
}

public sealed record LiveHttp01RenewalRequest
{
    private const int MaximumDnsNames = 100;
    private const int MaximumContacts = 10;

    public LiveHttp01RenewalRequest(
        Guid operationId,
        IEnumerable<string> dnsNames,
        Uri acmeDirectoryUri,
        IEnumerable<string>? contactUris,
        bool termsOfServiceAgreed,
        AcmeCertificateTrustMode certificateTrustMode,
        SecretReference acmeAccountKeyReference,
        RemoteSshConnectionOptions sshConnection,
        SecretReference sshPrivateKeyReference,
        RemotePosixPath challengeWebroot,
        RemotePosixPath incomingRoot,
        int tlsPort = 443,
        string? preferredChain = null)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "The operation identifier cannot be empty.",
                nameof(operationId));
        }

        ArgumentNullException.ThrowIfNull(dnsNames);
        ArgumentNullException.ThrowIfNull(acmeDirectoryUri);
        ArgumentNullException.ThrowIfNull(sshConnection);
        ArgumentNullException.ThrowIfNull(challengeWebroot);
        ArgumentNullException.ThrowIfNull(incomingRoot);

        if (!acmeDirectoryUri.IsAbsoluteUri ||
            !string.Equals(
                acmeDirectoryUri.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase) ||
            acmeDirectoryUri.AbsoluteUri.Length > 2_048 ||
            !string.IsNullOrEmpty(acmeDirectoryUri.UserInfo) ||
            !string.IsNullOrEmpty(acmeDirectoryUri.Fragment))
        {
            throw new ArgumentException(
                "The ACME directory must be a bounded absolute HTTPS URI without user information or a fragment.",
                nameof(acmeDirectoryUri));
        }

        if (!termsOfServiceAgreed)
        {
            throw new ArgumentException(
                "The ACME terms of service must be accepted before a live renewal.",
                nameof(termsOfServiceAgreed));
        }

        if (!Enum.IsDefined(certificateTrustMode))
        {
            throw new ArgumentOutOfRangeException(
                nameof(certificateTrustMode));
        }

        if (acmeAccountKeyReference.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A stable ACME account-key reference is required.",
                nameof(acmeAccountKeyReference));
        }

        if (sshPrivateKeyReference.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An SSH private-key reference is required.",
                nameof(sshPrivateKeyReference));
        }

        if (acmeAccountKeyReference.Value ==
            sshPrivateKeyReference.Value)
        {
            throw new ArgumentException(
                "ACME account and SSH credentials require distinct secret references.",
                nameof(acmeAccountKeyReference));
        }

        if (challengeWebroot == incomingRoot)
        {
            throw new ArgumentException(
                "The challenge webroot and certificate incoming root must be distinct.",
                nameof(incomingRoot));
        }

        if (tlsPort is < 1 or > 65_535)
        {
            throw new ArgumentOutOfRangeException(nameof(tlsPort));
        }

        OperationId = operationId;
        DnsNames = Array.AsReadOnly(NormalizeDnsNames(dnsNames));
        AcmeDirectoryUri = acmeDirectoryUri;
        ContactUris = Array.AsReadOnly(NormalizeContacts(contactUris));
        TermsOfServiceAgreed = termsOfServiceAgreed;
        CertificateTrustMode = certificateTrustMode;
        AcmeAccountKeyReference = acmeAccountKeyReference;
        SshConnection = sshConnection;
        SshPrivateKeyReference = sshPrivateKeyReference;
        ChallengeWebroot = challengeWebroot;
        IncomingRoot = incomingRoot;
        TlsPort = tlsPort;
        PreferredChain = NormalizePreferredChain(preferredChain);
    }

    public Guid OperationId { get; }

    public IReadOnlyList<string> DnsNames { get; }

    public string PrimaryDnsName => DnsNames[0];

    public Uri AcmeDirectoryUri { get; }

    public IReadOnlyList<string> ContactUris { get; }

    public bool TermsOfServiceAgreed { get; }

    public AcmeCertificateTrustMode CertificateTrustMode { get; }

    public SecretReference AcmeAccountKeyReference { get; }

    public RemoteSshConnectionOptions SshConnection { get; }

    public SecretReference SshPrivateKeyReference { get; }

    public RemotePosixPath ChallengeWebroot { get; }

    public RemotePosixPath IncomingRoot { get; }

    public int TlsPort { get; }

    public string? PreferredChain { get; }

    public TlsTrustPolicy TlsTrustPolicy => CertificateTrustMode switch
    {
        AcmeCertificateTrustMode.PubliclyTrusted => TlsTrustPolicy.System,
        AcmeCertificateTrustMode.UntrustedTest => TlsTrustPolicy.ExpectedLeaf,
        _ => throw new InvalidOperationException(
            "The ACME certificate trust mode is invalid."),
    };

    private static string[] NormalizeDnsNames(IEnumerable<string> dnsNames)
    {
        var normalized = new List<string>();
        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dnsName in dnsNames)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(dnsName);
            if (!string.Equals(dnsName, dnsName.Trim(), StringComparison.Ordinal) ||
                dnsName.StartsWith("*.", StringComparison.Ordinal) ||
                dnsName.Any(char.IsControl))
            {
                throw new ArgumentException(
                    "HTTP-01 requires non-wildcard DNS names without surrounding whitespace.",
                    nameof(dnsNames));
            }

            string asciiName;
            try
            {
                asciiName = new IdnMapping()
                    .GetAscii(dnsName.TrimEnd('.'))
                    .ToLowerInvariant();
            }
            catch (ArgumentException exception)
            {
                throw new ArgumentException(
                    "Every HTTP-01 identifier must be a valid DNS name.",
                    nameof(dnsNames),
                    exception);
            }

            if (asciiName.Length is < 1 or > 253 ||
                IPAddress.TryParse(asciiName, out _) ||
                Uri.CheckHostName(asciiName) != UriHostNameType.Dns)
            {
                throw new ArgumentException(
                    "Every HTTP-01 identifier must be a valid DNS name.",
                    nameof(dnsNames));
            }

            if (unique.Add(asciiName))
            {
                normalized.Add(asciiName);
            }

            if (normalized.Count > MaximumDnsNames)
            {
                throw new ArgumentException(
                    $"A renewal cannot contain more than {MaximumDnsNames} DNS names.",
                    nameof(dnsNames));
            }
        }

        if (normalized.Count == 0)
        {
            throw new ArgumentException(
                "At least one DNS name is required.",
                nameof(dnsNames));
        }

        return [.. normalized];
    }

    private static string[] NormalizeContacts(IEnumerable<string>? contactUris)
    {
        var normalized = (contactUris ?? [])
            .Select(static contact => contact?.Trim())
            .Where(static contact => !string.IsNullOrWhiteSpace(contact))
            .Select(static contact => contact!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (normalized.Length > MaximumContacts)
        {
            throw new ArgumentException(
                $"An ACME account cannot contain more than {MaximumContacts} contacts.",
                nameof(contactUris));
        }

        foreach (var contact in normalized)
        {
            if (contact.Length > 256 ||
                contact.Any(char.IsControl) ||
                !Uri.TryCreate(contact, UriKind.Absolute, out var contactUri) ||
                !string.Equals(
                    contactUri.Scheme,
                    "mailto",
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "Every ACME contact must be a bounded mailto URI.",
                    nameof(contactUris));
            }
        }

        return normalized;
    }

    private static string? NormalizePreferredChain(string? preferredChain)
    {
        if (string.IsNullOrWhiteSpace(preferredChain))
        {
            return null;
        }

        var normalized = preferredChain.Trim();
        if (normalized.Length > 200 || normalized.Any(char.IsControl))
        {
            throw new ArgumentException(
                "The preferred chain name must be bounded and contain no control characters.",
                nameof(preferredChain));
        }

        return normalized;
    }
}

public sealed record LiveRenewalResult
{
    public LiveRenewalResult(
        Guid operationId,
        LiveRenewalStatus status,
        string? failureCode,
        bool challengeCleanupVerified,
        bool publicTlsVerified,
        bool activationAttempted,
        bool rollbackAttempted,
        bool rollbackSucceeded,
        string? certificateLeafSha256,
        string? publicKeySha256,
        DateTimeOffset? notBeforeUtc,
        DateTimeOffset? notAfterUtc,
        SecretReference? certificatePrivateKeyReference,
        TlsTrustPolicy tlsTrustPolicy)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "The operation identifier cannot be empty.",
                nameof(operationId));
        }

        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        if (status == LiveRenewalStatus.Succeeded &&
            (!challengeCleanupVerified || !publicTlsVerified ||
             failureCode is not null))
        {
            throw new ArgumentException(
                "A successful renewal requires challenge-cleanup and public-TLS evidence.",
                nameof(status));
        }

        if (status != LiveRenewalStatus.Succeeded &&
            string.IsNullOrWhiteSpace(failureCode))
        {
            throw new ArgumentException(
                "An unsuccessful renewal requires a bounded failure code.",
                nameof(failureCode));
        }

        if (failureCode is not null &&
            (failureCode.Length > 128 ||
             failureCode.Any(
                 static character =>
                     !(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-'))))
        {
            throw new ArgumentException(
                "The failure code is invalid.",
                nameof(failureCode));
        }

        if (rollbackSucceeded && !rollbackAttempted)
        {
            throw new ArgumentException(
                "Rollback cannot succeed unless it was attempted.",
                nameof(rollbackSucceeded));
        }

        var hasCompleteCertificateMetadata =
            certificateLeafSha256 is not null &&
            publicKeySha256 is not null &&
            notBeforeUtc.HasValue &&
            notAfterUtc.HasValue &&
            certificatePrivateKeyReference.HasValue;
        if (status == LiveRenewalStatus.Succeeded &&
            !hasCompleteCertificateMetadata)
        {
            throw new ArgumentException(
                "A successful renewal requires complete issued-certificate metadata.",
                nameof(certificateLeafSha256));
        }

        if (notBeforeUtc.HasValue != notAfterUtc.HasValue ||
            (notBeforeUtc.HasValue && notAfterUtc <= notBeforeUtc))
        {
            throw new ArgumentException(
                "Certificate validity timestamps must form a valid pair.",
                nameof(notAfterUtc));
        }

        if (status == LiveRenewalStatus.RollbackRequired &&
            (!activationAttempted || rollbackSucceeded))
        {
            throw new ArgumentException(
                "Rollback-required status requires a potentially activated deployment that was not restored.",
                nameof(status));
        }

        OperationId = operationId;
        Status = status;
        FailureCode = failureCode;
        ChallengeCleanupVerified = challengeCleanupVerified;
        PublicTlsVerified = publicTlsVerified;
        ActivationAttempted = activationAttempted;
        RollbackAttempted = rollbackAttempted;
        RollbackSucceeded = rollbackSucceeded;
        CertificateLeafSha256 = certificateLeafSha256;
        PublicKeySha256 = publicKeySha256;
        NotBeforeUtc = notBeforeUtc?.ToUniversalTime();
        NotAfterUtc = notAfterUtc?.ToUniversalTime();
        CertificatePrivateKeyReference = certificatePrivateKeyReference;
        TlsTrustPolicy = tlsTrustPolicy;
    }

    public Guid OperationId { get; }

    public LiveRenewalStatus Status { get; }

    public string? FailureCode { get; }

    public bool ChallengeCleanupVerified { get; }

    public bool PublicTlsVerified { get; }

    public bool ActivationAttempted { get; }

    public bool RollbackAttempted { get; }

    public bool RollbackSucceeded { get; }

    public string? CertificateLeafSha256 { get; }

    /// <summary>
    /// Gets the SHA-256 digest of the certificate's DER SubjectPublicKeyInfo.
    /// </summary>
    public string? PublicKeySha256 { get; }

    public DateTimeOffset? NotBeforeUtc { get; }

    public DateTimeOffset? NotAfterUtc { get; }

    public SecretReference? CertificatePrivateKeyReference { get; }

    public TlsTrustPolicy TlsTrustPolicy { get; }
}
