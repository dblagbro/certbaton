using System.Security.Cryptography;

namespace CertBaton.Application.Remote;

public sealed class RemotePrivateKeyMaterial : IDisposable
{
    public const int MaximumPrivateKeyBytes = 1024 * 1024;
    private byte[]? _bytes;

    public RemotePrivateKeyMaterial(ReadOnlySpan<byte> privateKeyBytes)
    {
        if (privateKeyBytes.IsEmpty || privateKeyBytes.Length > MaximumPrivateKeyBytes)
        {
            throw new ArgumentException(
                $"Private key must contain 1 to {MaximumPrivateKeyBytes} bytes.",
                nameof(privateKeyBytes));
        }

        _bytes = privateKeyBytes.ToArray();
    }

    public int Length => GetBytes().Length;

    public Stream OpenReadStream() => new MemoryStream(GetBytes(), writable: false);

    public void Dispose()
    {
        var bytes = Interlocked.Exchange(ref _bytes, null);
        if (bytes is not null)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private byte[] GetBytes() => _bytes ?? throw new ObjectDisposedException(nameof(RemotePrivateKeyMaterial));
}
