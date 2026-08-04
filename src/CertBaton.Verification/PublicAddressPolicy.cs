using System.Net;
using System.Net.Sockets;

namespace CertBaton.Verification;

internal static class PublicAddressPolicy
{
    private static readonly (byte[] Prefix, int Length)[]
        nonPublicGlobalUnicastIpv6Prefixes =
        [
            (IPAddress.Parse("2001::").GetAddressBytes(), 23),
            (IPAddress.Parse("2001:db8::").GetAddressBytes(), 32),
            (IPAddress.Parse("2002::").GetAddressBytes(), 16),
            (IPAddress.Parse("3fff::").GetAddressBytes(), 20),
        ];

    public static bool IsPublic(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (IPAddress.IsLoopback(address) ||
            address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.None) ||
            address.Equals(IPAddress.IPv6None))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6 &&
            address.ScopeId != 0)
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return IsPublic(address.MapToIPv4());
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] != 0 &&
                bytes[0] != 10 &&
                bytes[0] != 127 &&
                !(bytes[0] == 169 && bytes[1] == 254) &&
                !(bytes[0] == 172 && bytes[1] is >= 16 and <= 31) &&
                !(bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0) &&
                !(bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2) &&
                !(bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99) &&
                !(bytes[0] == 192 && bytes[1] == 168) &&
                !(bytes[0] == 100 && bytes[1] is >= 64 and <= 127) &&
                !(bytes[0] == 198 && bytes[1] is 18 or 19) &&
                !(bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) &&
                !(bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) &&
                bytes[0] < 224;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            return (bytes[0] & 0xE0) == 0x20 &&
                !nonPublicGlobalUnicastIpv6Prefixes.Any(
                    prefix => IsInPrefix(
                        bytes,
                        prefix.Prefix,
                        prefix.Length));
        }

        return false;
    }

    private static bool IsInPrefix(
        ReadOnlySpan<byte> address,
        ReadOnlySpan<byte> prefix,
        int prefixLength)
    {
        var completeBytes = prefixLength / 8;
        if (!address[..completeBytes].SequenceEqual(prefix[..completeBytes]))
        {
            return false;
        }

        var remainingBits = prefixLength % 8;
        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (address[completeBytes] & mask) ==
            (prefix[completeBytes] & mask);
    }
}
