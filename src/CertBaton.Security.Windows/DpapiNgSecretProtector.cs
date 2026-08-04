using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

namespace CertBaton.Security.Windows;

public sealed partial class DpapiNgSecretProtector
{
    private const uint SilentFlag = 0x00000040;
    private readonly string protectionDescriptor;

    private DpapiNgSecretProtector(string protectionDescriptor)
    {
        this.protectionDescriptor = protectionDescriptor;
    }

    public DpapiNgSecretProtector(SecurityIdentifier authorizedSid)
    {
        ArgumentNullException.ThrowIfNull(authorizedSid);
        protectionDescriptor = $"SID={authorizedSid.Value}";
    }

    public static DpapiNgSecretProtector ForCurrentUser() =>
        new("LOCAL=user");

    public byte[] Protect(ReadOnlySpan<byte> secret)
    {
        if (secret.IsEmpty)
        {
            throw new ArgumentException(
                "A protected secret cannot be empty.",
                nameof(secret));
        }

        var secretCopy = secret.ToArray();
        try
        {
            var status = NativeMethods.NCryptCreateProtectionDescriptor(
                protectionDescriptor,
                0,
                out var descriptor);
            ThrowIfFailed("descriptor creation", status);
            try
            {
                status = NativeMethods.NCryptProtectSecret(
                    descriptor,
                    SilentFlag,
                    secretCopy,
                    checked((uint)secretCopy.Length),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out var protectedBuffer,
                    out var protectedLength);
                ThrowIfFailed("protection", status);
                return CopyAndFree(protectedBuffer, protectedLength);
            }
            finally
            {
                if (descriptor != IntPtr.Zero)
                {
                    _ = NativeMethods.NCryptCloseProtectionDescriptor(
                        descriptor);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretCopy);
        }
    }

    public static byte[] Unprotect(ReadOnlySpan<byte> protectedSecret)
    {
        if (protectedSecret.IsEmpty)
        {
            throw new ArgumentException(
                "A protected secret blob cannot be empty.",
                nameof(protectedSecret));
        }

        var protectedCopy = protectedSecret.ToArray();
        try
        {
            var status = NativeMethods.NCryptUnprotectSecret(
                IntPtr.Zero,
                SilentFlag,
                protectedCopy,
                checked((uint)protectedCopy.Length),
                IntPtr.Zero,
                IntPtr.Zero,
                out var plaintextBuffer,
                out var plaintextLength);
            ThrowIfFailed("unprotection", status);
            return CopyAndFree(plaintextBuffer, plaintextLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedCopy);
        }
    }

    private static byte[] CopyAndFree(IntPtr buffer, uint length)
    {
        if (buffer == IntPtr.Zero)
        {
            throw new CryptographicException(
                "DPAPI-NG returned an empty output buffer.");
        }

        try
        {
            var result = new byte[checked((int)length)];
            Marshal.Copy(buffer, result, 0, result.Length);
            return result;
        }
        finally
        {
            _ = NativeMethods.LocalFree(buffer);
        }
    }

    private static void ThrowIfFailed(string operation, int status)
    {
        if (status != 0)
        {
            throw new DpapiNgException(operation, status);
        }
    }

    private static partial class NativeMethods
    {
        [LibraryImport(
            "ncrypt.dll",
            EntryPoint = "NCryptCreateProtectionDescriptor",
            StringMarshalling = StringMarshalling.Utf16)]
        internal static partial int NCryptCreateProtectionDescriptor(
            string descriptorString,
            uint flags,
            out IntPtr descriptor);

        [LibraryImport("ncrypt.dll", EntryPoint = "NCryptProtectSecret")]
        internal static partial int NCryptProtectSecret(
            IntPtr descriptor,
            uint flags,
            byte[] data,
            uint dataLength,
            IntPtr memoryParameters,
            IntPtr parentWindow,
            out IntPtr protectedBlob,
            out uint protectedBlobLength);

        [LibraryImport("ncrypt.dll", EntryPoint = "NCryptUnprotectSecret")]
        internal static partial int NCryptUnprotectSecret(
            IntPtr descriptor,
            uint flags,
            byte[] protectedBlob,
            uint protectedBlobLength,
            IntPtr memoryParameters,
            IntPtr parentWindow,
            out IntPtr data,
            out uint dataLength);

        [LibraryImport("kernel32.dll")]
        internal static partial IntPtr LocalFree(IntPtr memory);
    }

    private static partial class NativeMethods
    {
        [LibraryImport(
            "ncrypt.dll",
            EntryPoint = "NCryptCloseProtectionDescriptor")]
        internal static partial int NCryptCloseProtectionDescriptor(
            IntPtr descriptor);
    }
}
