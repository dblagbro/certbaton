using System.Security.Cryptography;
using CertBaton.Application.Security;

namespace CertBaton.Security.Windows;

public sealed class ProtectedFileSecretVault : ISecretVault
{
    public const int MaximumSecretLength = 1024 * 1024;
    public const int MaximumProtectedLength = 2 * 1024 * 1024;
    private readonly string rootPath;
    private readonly DpapiNgSecretProtector protector;

    public ProtectedFileSecretVault(
        string rootPath,
        DpapiNgSecretProtector protector)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        ArgumentNullException.ThrowIfNull(protector);

        this.rootPath = Path.GetFullPath(rootPath);
        this.protector = protector;
        Directory.CreateDirectory(this.rootPath);
        ThrowIfReparsePoint(this.rootPath);
    }

    public bool Contains(SecretReference reference) =>
        File.Exists(GetPath(reference));

    public void Store(
        SecretReference reference,
        ReadOnlySpan<byte> secret,
        bool replace = false)
    {
        if (secret.IsEmpty || secret.Length > MaximumSecretLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(secret),
                $"A secret must contain between 1 and {MaximumSecretLength} bytes.");
        }

        var protectedSecret = protector.Protect(secret);
        try
        {
            WriteProtected(reference, protectedSecret, replace);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedSecret);
        }
    }

    public void ImportProtected(
        SecretReference reference,
        ReadOnlySpan<byte> protectedSecret,
        bool replace = false)
    {
        if (protectedSecret.IsEmpty ||
            protectedSecret.Length > MaximumProtectedLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(protectedSecret),
                $"A protected secret must contain between 1 and {MaximumProtectedLength} bytes.");
        }

        var plaintext = DpapiNgSecretProtector.Unprotect(protectedSecret);
        try
        {
            if (plaintext.Length > MaximumSecretLength)
            {
                throw new InvalidDataException(
                    "The protected secret exceeds the vault plaintext limit.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        WriteProtected(reference, protectedSecret, replace);
    }

    public byte[] Read(SecretReference reference)
    {
        var path = GetPath(reference);
        ThrowIfReparsePoint(path);
        var protectedSecret = File.ReadAllBytes(path);
        try
        {
            if (protectedSecret.Length == 0 ||
                protectedSecret.Length > MaximumProtectedLength)
            {
                throw new InvalidDataException(
                    "The protected secret record has an invalid length.");
            }

            return DpapiNgSecretProtector.Unprotect(protectedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedSecret);
        }
    }

    public bool Delete(SecretReference reference)
    {
        var path = GetPath(reference);
        if (!File.Exists(path))
        {
            return false;
        }

        ThrowIfReparsePoint(path);
        File.Delete(path);
        return true;
    }

    private void WriteProtected(
        SecretReference reference,
        ReadOnlySpan<byte> protectedSecret,
        bool replace)
    {
        var destinationPath = GetPath(reference);
        if (!replace && File.Exists(destinationPath))
        {
            throw new IOException(
                $"Secret reference '{reference}' already exists.");
        }

        ThrowIfReparsePoint(rootPath);
        if (File.Exists(destinationPath))
        {
            ThrowIfReparsePoint(destinationPath);
        }

        var temporaryPath = Path.Combine(
            rootPath,
            $".{reference.Value:N}.{Guid.CreateVersion7():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(protectedSecret);
                stream.Flush(true);
            }

            File.Move(temporaryPath, destinationPath, replace);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private string GetPath(SecretReference reference) =>
        Path.Combine(rootPath, $"{reference.Value:N}.secret");

    private static void ThrowIfReparsePoint(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            return;
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                $"Secret-vault paths cannot be reparse points: '{path}'.");
        }
    }
}
