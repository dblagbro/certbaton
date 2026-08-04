using CertBaton.Application.Security;
using CertBaton.Contracts;

namespace CertBaton.Service;

public interface ICredentialImporter
{
    CredentialImportSnapshot ImportSshPrivateKey(ReadOnlySpan<byte> privateKey);
}

public sealed class CredentialImporter(
    ISecretVault vault,
    TimeProvider timeProvider) : ICredentialImporter
{
    private static ReadOnlySpan<byte> OpenSshHeader =>
        "-----BEGIN OPENSSH PRIVATE KEY-----"u8;

    private static ReadOnlySpan<byte> Pkcs8Header =>
        "-----BEGIN PRIVATE KEY-----"u8;

    public CredentialImportSnapshot ImportSshPrivateKey(
        ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length == 0 ||
            privateKey.Length > CredentialContractValues.MaximumSecretBytes ||
            (!privateKey.StartsWith(OpenSshHeader) &&
             !privateKey.StartsWith(Pkcs8Header)))
        {
            throw new InvalidDataException(
                "The selected file is not a supported OpenSSH or PKCS #8 private key.");
        }

        var reference = new SecretReference(Guid.CreateVersion7());
        vault.Store(reference, privateKey);
        return new CredentialImportSnapshot(
            reference.Value,
            CredentialContractValues.SshPrivateKeyKind,
            timeProvider.GetUtcNow().ToUniversalTime());
    }
}
