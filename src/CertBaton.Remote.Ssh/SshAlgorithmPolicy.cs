using CertBaton.Application.Remote;
using Renci.SshNet;

namespace CertBaton.Remote.Ssh;

internal static class SshAlgorithmPolicy
{
    internal static void Apply(ConnectionInfo connectionInfo, SshHostKeyPin pin)
    {
        ArgumentNullException.ThrowIfNull(connectionInfo);
        ArgumentNullException.ThrowIfNull(pin);

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

    private static void RemoveMatching<T>(IDictionary<string, T> algorithms, Func<string, bool> predicate)
    {
        foreach (var name in algorithms.Keys.Where(predicate).ToArray())
        {
            algorithms.Remove(name);
        }
    }
}
