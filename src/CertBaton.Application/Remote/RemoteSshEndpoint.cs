using System.Globalization;
using System.Net;
using System.Text;

namespace CertBaton.Application.Remote;

public sealed record RemoteSshEndpoint
{
    private const int MaximumHostLength = 253;
    private const int MaximumUsernameBytes = 128;

    private RemoteSshEndpoint(string host, int port, string username)
    {
        Host = host;
        Port = port;
        Username = username;
    }

    public string Host { get; }

    public int Port { get; }

    public string Username { get; }

    public static RemoteSshEndpoint Create(string host, int port, string username)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(username);

        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "SSH port must be between 1 and 65535.");
        }

        var normalizedHost = NormalizeHost(host);
        ValidateUsername(username);
        return new RemoteSshEndpoint(normalizedHost, port, username);
    }

    public static string NormalizeHost(string host)
    {
        ArgumentNullException.ThrowIfNull(host);

        if (host.Length == 0 || !string.Equals(host, host.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException("SSH host cannot be empty or contain surrounding whitespace.", nameof(host));
        }

        if (IPAddress.TryParse(host, out var address))
        {
            return address.ToString().ToLowerInvariant();
        }

        var dnsName = host.EndsWith('.') ? host[..^1] : host;
        if (dnsName.Length == 0)
        {
            throw new ArgumentException("SSH host must identify a DNS name or IP address.", nameof(host));
        }

        string asciiHost;
        try
        {
            asciiHost = new IdnMapping().GetAscii(dnsName).ToLowerInvariant();
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException("SSH host is not a valid DNS name.", nameof(host), exception);
        }

        if (asciiHost.Length > MaximumHostLength)
        {
            throw new ArgumentException($"SSH host cannot exceed {MaximumHostLength} ASCII characters.", nameof(host));
        }

        foreach (var label in asciiHost.Split('.'))
        {
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-')
            {
                throw new ArgumentException("SSH host contains an invalid DNS label.", nameof(host));
            }

            foreach (var character in label)
            {
                if (!IsAsciiLetterOrDigit(character) && character != '-')
                {
                    throw new ArgumentException("SSH host contains an invalid DNS character.", nameof(host));
                }
            }
        }

        return asciiHost;
    }

    private static void ValidateUsername(string username)
    {
        if (username.Length == 0 || !string.Equals(username, username.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException("SSH username cannot be empty or contain surrounding whitespace.", nameof(username));
        }

        if (Encoding.UTF8.GetByteCount(username) > MaximumUsernameBytes)
        {
            throw new ArgumentException($"SSH username cannot exceed {MaximumUsernameBytes} UTF-8 bytes.", nameof(username));
        }

        foreach (var character in username)
        {
            if (!IsAsciiLetterOrDigit(character) && character is not ('.' or '_' or '-' or '@'))
            {
                throw new ArgumentException(
                    "SSH username may contain only ASCII letters, digits, period, underscore, hyphen, or at sign.",
                    nameof(username));
            }
        }
    }

    private static bool IsAsciiLetterOrDigit(char character) =>
        character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
}
