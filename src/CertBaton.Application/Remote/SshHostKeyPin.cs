using System.Security.Cryptography;

namespace CertBaton.Application.Remote;

public sealed class SshHostKeyPin
{
    private const int Sha256Length = 32;
    private const int MaximumRawHostKeyBytes = 65_536;
    private static readonly HashSet<string> AllowedAlgorithms = new(StringComparer.Ordinal)
    {
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-256",
        "rsa-sha2-512",
    };

    private readonly byte[] _fingerprint;
    private readonly byte[]? _rawHostKey;

    private SshHostKeyPin(
        string host,
        int port,
        string algorithm,
        byte[] fingerprint,
        byte[]? rawHostKey)
    {
        Host = host;
        Port = port;
        Algorithm = algorithm;
        _fingerprint = fingerprint;
        _rawHostKey = rawHostKey;
        FingerprintSha256 = "SHA256:" + Convert.ToBase64String(fingerprint).TrimEnd('=');
    }

    public string Host { get; }

    public int Port { get; }

    public string Algorithm { get; }

    public string FingerprintSha256 { get; }

    public bool HasRawHostKey => _rawHostKey is not null;

    public static SshHostKeyPin Create(
        string host,
        int port,
        string algorithm,
        string fingerprintSha256,
        ReadOnlySpan<byte> rawHostKey = default)
    {
        var normalizedHost = RemoteSshEndpoint.NormalizeHost(host);
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "SSH port must be between 1 and 65535.");
        }

        ArgumentNullException.ThrowIfNull(algorithm);
        if (!AllowedAlgorithms.Contains(algorithm))
        {
            throw new ArgumentException("Host-key algorithm is unsupported or does not meet the minimum security policy.", nameof(algorithm));
        }

        var fingerprint = ParseFingerprint(fingerprintSha256);
        byte[]? rawCopy = null;
        if (!rawHostKey.IsEmpty)
        {
            if (rawHostKey.Length > MaximumRawHostKeyBytes)
            {
                throw new ArgumentException($"Raw host key cannot exceed {MaximumRawHostKeyBytes} bytes.", nameof(rawHostKey));
            }

            rawCopy = rawHostKey.ToArray();
            var computedFingerprint = SHA256.HashData(rawCopy);
            if (!CryptographicOperations.FixedTimeEquals(computedFingerprint, fingerprint))
            {
                throw new ArgumentException("Raw host key does not match the supplied SHA-256 fingerprint.", nameof(rawHostKey));
            }
        }

        return new SshHostKeyPin(normalizedHost, port, algorithm, fingerprint, rawCopy);
    }

    public byte[]? ExportRawHostKey() => _rawHostKey?.ToArray();

    public bool Matches(RemoteSshEndpoint endpoint, string algorithm, ReadOnlySpan<byte> rawHostKey)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(algorithm);

        if (!string.Equals(Host, endpoint.Host, StringComparison.Ordinal)
            || Port != endpoint.Port
            || !string.Equals(Algorithm, algorithm, StringComparison.Ordinal)
            || rawHostKey.IsEmpty)
        {
            return false;
        }

        var candidateFingerprint = SHA256.HashData(rawHostKey);
        if (!CryptographicOperations.FixedTimeEquals(candidateFingerprint, _fingerprint))
        {
            return false;
        }

        return _rawHostKey is null || CryptographicOperations.FixedTimeEquals(rawHostKey, _rawHostKey);
    }

    private static byte[] ParseFingerprint(string fingerprintSha256)
    {
        ArgumentNullException.ThrowIfNull(fingerprintSha256);
        const string prefix = "SHA256:";
        var encoded = fingerprintSha256.StartsWith(prefix, StringComparison.Ordinal)
            ? fingerprintSha256[prefix.Length..]
            : fingerprintSha256;

        if (encoded.Length == 0 || encoded.Contains('=', StringComparison.Ordinal))
        {
            throw new ArgumentException("SHA-256 fingerprint must use canonical unpadded base64.", nameof(fingerprintSha256));
        }

        try
        {
            var paddingLength = (4 - (encoded.Length % 4)) % 4;
            var decoded = Convert.FromBase64String(encoded + new string('=', paddingLength));
            if (decoded.Length != Sha256Length
                || !string.Equals(Convert.ToBase64String(decoded).TrimEnd('='), encoded, StringComparison.Ordinal))
            {
                throw new ArgumentException("SHA-256 fingerprint is not canonical.", nameof(fingerprintSha256));
            }

            return decoded;
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("SHA-256 fingerprint must use canonical unpadded base64.", nameof(fingerprintSha256), exception);
        }
    }
}
