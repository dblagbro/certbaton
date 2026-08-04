using CertBaton.Application.Remote;
using Renci.SshNet;

namespace CertBaton.Remote.Ssh;

internal static class SshAlgorithmPolicy
{
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

    internal static void Apply(ConnectionInfo connectionInfo, SshHostKeyPin pin)
    {
        ArgumentNullException.ThrowIfNull(connectionInfo);
        ArgumentNullException.ThrowIfNull(pin);

        ApplyBaseline(connectionInfo);

        foreach (var name in connectionInfo.HostKeyAlgorithms.Keys.ToArray())
        {
            if (!string.Equals(name, pin.Algorithm, StringComparison.Ordinal))
            {
                connectionInfo.HostKeyAlgorithms.Remove(name);
            }
        }

        if (connectionInfo.HostKeyAlgorithms.Count == 0)
        {
            throw new NotSupportedException($"SSH.NET does not support the pinned host-key algorithm '{pin.Algorithm}'.");
        }
    }

    internal static void ApplyForDiscovery(ConnectionInfo connectionInfo)
    {
        ArgumentNullException.ThrowIfNull(connectionInfo);
        ApplyBaseline(connectionInfo);
        RemoveMatching(
            connectionInfo.HostKeyAlgorithms,
            static name => !allowedHostKeyAlgorithms.Contains(name));

        if (connectionInfo.HostKeyAlgorithms.Count == 0)
        {
            throw new NotSupportedException(
                "SSH.NET does not offer a host-key algorithm allowed by CertBaton.");
        }
    }

    internal static bool IsAllowedHostKeyAlgorithm(string algorithm) =>
        allowedHostKeyAlgorithms.Contains(algorithm);

    private static void ApplyBaseline(ConnectionInfo connectionInfo)
    {
        RemoveMatching(connectionInfo.KeyExchangeAlgorithms, static name =>
            name.Contains("sha1", StringComparison.OrdinalIgnoreCase)
            || name.Contains("group1", StringComparison.OrdinalIgnoreCase));

        RemoveMatching(connectionInfo.Encryptions, static name =>
            name.Contains("-cbc", StringComparison.OrdinalIgnoreCase)
            || name.Contains("3des", StringComparison.OrdinalIgnoreCase)
            || name.Contains("blowfish", StringComparison.OrdinalIgnoreCase)
            || name.Contains("cast128", StringComparison.OrdinalIgnoreCase)
            || name.Contains("arcfour", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "none", StringComparison.OrdinalIgnoreCase));

        RemoveMatching(connectionInfo.HmacAlgorithms, static name =>
            name.Contains("md5", StringComparison.OrdinalIgnoreCase)
            || name.Contains("sha1", StringComparison.OrdinalIgnoreCase)
            || name.Contains("ripemd", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "none", StringComparison.OrdinalIgnoreCase));

    }

    private static void RemoveMatching<T>(IDictionary<string, T> algorithms, Func<string, bool> predicate)
    {
        foreach (var name in algorithms.Keys.Where(predicate).ToArray())
        {
            algorithms.Remove(name);
        }
    }
}
