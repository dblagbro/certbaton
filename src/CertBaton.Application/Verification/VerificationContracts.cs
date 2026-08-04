using System.Net;

namespace CertBaton.Application.Verification;

public enum TlsTrustPolicy
{
    System = 0,
    ExpectedLeaf = 1,
}

public sealed record Http01VerificationRequest
{
    public Http01VerificationRequest(
        Uri challengeUri,
        string expectedKeyAuthorization,
        int maximumRedirects = 10)
    {
        ArgumentNullException.ThrowIfNull(challengeUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedKeyAuthorization);
        if (!challengeUri.IsAbsoluteUri ||
            !string.Equals(challengeUri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) ||
            challengeUri.Port != 80)
        {
            throw new ArgumentException(
                "An HTTP-01 verification URI must be an absolute HTTP URI on port 80.",
                nameof(challengeUri));
        }

        if (maximumRedirects is < 0 or > 10)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumRedirects),
                "HTTP-01 verification permits between zero and ten redirects.");
        }

        ChallengeUri = challengeUri;
        ExpectedKeyAuthorization = expectedKeyAuthorization;
        MaximumRedirects = maximumRedirects;
    }

    public Uri ChallengeUri { get; }

    public string ExpectedKeyAuthorization { get; }

    public int MaximumRedirects { get; }
}

public sealed record Http01VerificationResult(
    bool Success,
    string Code,
    Uri FinalUri,
    HttpStatusCode? StatusCode,
    int RedirectCount,
    IReadOnlyList<IPAddress> ResolvedAddresses);

public sealed record PublicTlsVerificationRequest
{
    public PublicTlsVerificationRequest(
        string hostname,
        int port,
        string expectedLeafSha256,
        TlsTrustPolicy trustPolicy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostname);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedLeafSha256);
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        var normalizedFingerprint = expectedLeafSha256
            .Replace(":", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();
        if (normalizedFingerprint.Length != 64 ||
            normalizedFingerprint.Any(
                static character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException(
                "The expected leaf fingerprint must be a SHA-256 hexadecimal value.",
                nameof(expectedLeafSha256));
        }

        Hostname = hostname.Trim().TrimEnd('.').ToLowerInvariant();
        Port = port;
        ExpectedLeafSha256 = normalizedFingerprint;
        TrustPolicy = trustPolicy;
    }

    public string Hostname { get; }

    public int Port { get; }

    public string ExpectedLeafSha256 { get; }

    public TlsTrustPolicy TrustPolicy { get; }
}

public sealed record PublicTlsVerificationResult(
    bool Success,
    string Code,
    string? ObservedLeafSha256,
    DateTimeOffset? NotBeforeUtc,
    DateTimeOffset? NotAfterUtc,
    bool HostnameMatched,
    bool ChainTrusted,
    IReadOnlyList<IPAddress> ResolvedAddresses);

public sealed record CertificateInspectionResult(
    bool Success,
    string Code,
    string? LeafSha256,
    DateTimeOffset? NotBeforeUtc,
    DateTimeOffset? NotAfterUtc);

public interface IPublicHttp01Verifier
{
    Task<Http01VerificationResult> VerifyAsync(
        Http01VerificationRequest request,
        CancellationToken cancellationToken);
}

public interface IPublicTlsVerifier
{
    Task<PublicTlsVerificationResult> VerifyAsync(
        PublicTlsVerificationRequest request,
        CancellationToken cancellationToken);
}

public interface ICertificateMaterialInspector
{
    CertificateInspectionResult Inspect(
        string certificateChainPem,
        string privateKeyPem,
        string expectedHostname,
        DateTimeOffset nowUtc);
}
