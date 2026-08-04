using System.Globalization;
using System.Net;
using System.Security.Cryptography;

namespace CertBaton.Domain.Connections;

public readonly record struct ConnectionId
{
    public ConnectionId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "A connection identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static ConnectionId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public sealed record ConnectionEndpoint
{
    public ConnectionEndpoint(string host, int port = 22)
    {
        Host = NormalizeHost(host);
        if (port is < 1 or > 65_535)
        {
            throw new ArgumentOutOfRangeException(
                nameof(port),
                port,
                "A connection port must be between 1 and 65535.");
        }

        Port = port;
    }

    public string Host { get; }

    public int Port { get; }

    private static string NormalizeHost(string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (host.Length > 253 ||
            !string.Equals(host, host.Trim(), StringComparison.Ordinal) ||
            host.Any(char.IsControl))
        {
            throw new ArgumentException(
                "A connection host must be a bounded hostname or IP address without surrounding whitespace.",
                nameof(host));
        }

        if (IPAddress.TryParse(host, out var address))
        {
            return address.ToString();
        }

        string asciiHost;
        try
        {
            asciiHost = new IdnMapping().GetAscii(host.TrimEnd('.'));
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException(
                "A connection host must be a valid hostname or IP address.",
                nameof(host),
                exception);
        }

        if (asciiHost.Length is < 1 or > 253 ||
            Uri.CheckHostName(asciiHost) != UriHostNameType.Dns)
        {
            throw new ArgumentException(
                "A connection host must be a valid hostname or IP address.",
                nameof(host));
        }

        return asciiHost.ToLowerInvariant();
    }
}

public sealed record ConnectionProfile
{
    private const int MaximumRawHostKeyBytes = 65_536;
    private static readonly HashSet<string> allowedHostKeyAlgorithms =
        new(StringComparer.Ordinal)
        {
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "rsa-sha2-256",
            "rsa-sha2-512",
        };
    private readonly byte[]? rawHostKey;

    public ConnectionProfile(
        ConnectionId id,
        string displayName,
        ConnectionEndpoint endpoint,
        string username,
        string credentialReference,
        string? hostKeyAlgorithm,
        string hostKeyFingerprint,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc,
        bool enabled = true,
        ReadOnlySpan<byte> rawHostKey = default)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A connection identifier cannot be empty.",
                nameof(id));
        }

        ArgumentNullException.ThrowIfNull(endpoint);
        Id = id;
        DisplayName = ValidateText(displayName, 100, nameof(displayName));
        Endpoint = endpoint;
        Username = ValidateText(username, 128, nameof(username));
        CredentialReference = ValidateText(
            credentialReference,
            200,
            nameof(credentialReference));
        HostKeyFingerprint = ValidateText(
            hostKeyFingerprint,
            200,
            nameof(hostKeyFingerprint),
            minimumLength: 16);
        if (hostKeyAlgorithm is null)
        {
            if (enabled || !rawHostKey.IsEmpty)
            {
                throw new ArgumentException(
                    "An enabled connection or raw host key requires an enrolled host-key algorithm.",
                    nameof(hostKeyAlgorithm));
            }
        }
        else if (!allowedHostKeyAlgorithms.Contains(hostKeyAlgorithm))
        {
            throw new ArgumentException(
                "The SSH host-key algorithm is unsupported or does not meet policy.",
                nameof(hostKeyAlgorithm));
        }

        if (hostKeyAlgorithm is not null)
        {
            var fingerprint = ParseFingerprint(HostKeyFingerprint);
            if (!rawHostKey.IsEmpty)
            {
                if (rawHostKey.Length > MaximumRawHostKeyBytes)
                {
                    throw new ArgumentException(
                        $"A raw SSH host key cannot exceed {MaximumRawHostKeyBytes} bytes.",
                        nameof(rawHostKey));
                }

                var computedFingerprint = SHA256.HashData(rawHostKey);
                if (!CryptographicOperations.FixedTimeEquals(
                        computedFingerprint,
                        fingerprint))
                {
                    throw new ArgumentException(
                        "The raw SSH host key does not match its SHA-256 fingerprint.",
                        nameof(rawHostKey));
                }

                this.rawHostKey = rawHostKey.ToArray();
            }
        }

        HostKeyAlgorithm = hostKeyAlgorithm;
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

    public ConnectionId Id { get; }

    public string DisplayName { get; }

    public ConnectionEndpoint Endpoint { get; }

    public string Username { get; }

    public string CredentialReference { get; }

    public string? HostKeyAlgorithm { get; }

    public string HostKeyFingerprint { get; }

    public bool HasRawHostKey => rawHostKey is not null;

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; }

    public bool Enabled { get; }

    public byte[]? ExportRawHostKey() => rawHostKey?.ToArray();

    private static byte[] ParseFingerprint(string value)
    {
        const string prefix = "SHA256:";
        var encoded = value.StartsWith(prefix, StringComparison.Ordinal)
            ? value[prefix.Length..]
            : value;
        if (encoded.Length == 0 || encoded.Contains('=', StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The SSH fingerprint must use canonical unpadded SHA-256 base64.",
                nameof(value));
        }

        try
        {
            var paddingLength = (4 - (encoded.Length % 4)) % 4;
            var decoded = Convert.FromBase64String(
                encoded + new string('=', paddingLength));
            if (decoded.Length != 32 ||
                !string.Equals(
                    Convert.ToBase64String(decoded).TrimEnd('='),
                    encoded,
                    StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "The SSH fingerprint must use canonical unpadded SHA-256 base64.",
                    nameof(value));
            }

            return decoded;
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "The SSH fingerprint must use canonical unpadded SHA-256 base64.",
                nameof(value),
                exception);
        }
    }

    private static string ValidateText(
        string value,
        int maximumLength,
        string parameterName,
        int minimumLength = 1)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length < minimumLength ||
            value.Length > maximumLength ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException(
                "The value has an invalid length, surrounding whitespace, or control character.",
                parameterName);
        }

        return value;
    }
}
