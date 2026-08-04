using System.Security.Cryptography;
using CertBaton.Application.Security;
using CertBaton.Contracts;

namespace CertBaton.Service;

public interface IVaultProbe
{
    VaultProbeSnapshot Run();
}

public sealed class VaultProbe(
    ISecretVault vault,
    TimeProvider timeProvider) : IVaultProbe
{
    public VaultProbeSnapshot Run()
    {
        var reference = new SecretReference(Guid.CreateVersion7());
        var canary = RandomNumberGenerator.GetBytes(32);
        byte[]? recovered = null;
        var verified = false;
        var removed = false;
        try
        {
            vault.Store(reference, canary);
            recovered = vault.Read(reference);
            verified = CryptographicOperations.FixedTimeEquals(
                canary,
                recovered);
            if (!verified)
            {
                throw new CryptographicException(
                    "The service vault did not reproduce its one-time canary.");
            }
        }
        finally
        {
            removed = vault.Delete(reference);
            CryptographicOperations.ZeroMemory(canary);
            if (recovered is not null)
            {
                CryptographicOperations.ZeroMemory(recovered);
            }
        }

        if (!removed)
        {
            throw new IOException(
                "The service vault did not remove its one-time probe record.");
        }

        return new VaultProbeSnapshot(
            "healthy",
            verified,
            removed,
            timeProvider.GetUtcNow().ToUniversalTime());
    }
}
