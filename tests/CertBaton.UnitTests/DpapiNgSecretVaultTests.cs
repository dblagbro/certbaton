using System.Security.Cryptography;
using CertBaton.Application.Security;
using CertBaton.Security.Windows;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class DpapiNgSecretVaultTests
{
    [TestMethod]
    public void CurrentIdentityCanRoundTripSidProtectedSecret()
    {
        var protector = DpapiNgSecretProtector.ForCurrentUser();
        var plaintext = "vault-canary"u8.ToArray();
        byte[]? protectedSecret = null;
        byte[]? recovered = null;
        try
        {
            protectedSecret = protector.Protect(plaintext);
            recovered = DpapiNgSecretProtector.Unprotect(protectedSecret);

            CollectionAssert.AreEqual(plaintext, recovered);
            Assert.IsFalse(plaintext.SequenceEqual(protectedSecret));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedSecret is not null)
            {
                CryptographicOperations.ZeroMemory(protectedSecret);
            }

            if (recovered is not null)
            {
                CryptographicOperations.ZeroMemory(recovered);
            }
        }
    }

    [TestMethod]
    public void VaultStoresOnlyProtectedBytesAndSupportsExplicitReplacement()
    {
        var protector = DpapiNgSecretProtector.ForCurrentUser();
        var root = Path.Combine(
            Path.GetTempPath(),
            $"certbaton-vault-{Guid.CreateVersion7():N}");
        Directory.CreateDirectory(root);
        try
        {
            var vault = new ProtectedFileSecretVault(root, protector);
            var reference = new SecretReference(
                Guid.Parse("019c0d23-8b0a-7d6e-a222-6645cb8dc521"));
            var original = "first-canary"u8.ToArray();
            var replacement = "second-canary"u8.ToArray();
            try
            {
                vault.Store(reference, original);
                Assert.IsTrue(vault.Contains(reference));
                Assert.ThrowsExactly<IOException>(
                    () => vault.Store(reference, replacement));

                var file = Directory.GetFiles(root, "*.secret").Single();
                var storedBytes = File.ReadAllBytes(file);
                Assert.IsFalse(
                    storedBytes.AsSpan().IndexOf(original) >= 0,
                    "The vault record unexpectedly contains the plaintext canary.");

                vault.Store(reference, replacement, replace: true);
                var recovered = vault.Read(reference);
                try
                {
                    CollectionAssert.AreEqual(replacement, recovered);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(recovered);
                }

                Assert.IsTrue(vault.Delete(reference));
                Assert.IsFalse(vault.Delete(reference));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(original);
                CryptographicOperations.ZeroMemory(replacement);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    public void ImportRejectsBlobThatCannotBeUnprotectedByCurrentIdentity()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"certbaton-vault-{Guid.CreateVersion7():N}");
        Directory.CreateDirectory(root);
        try
        {
            var vault = new ProtectedFileSecretVault(
                root,
                DpapiNgSecretProtector.ForCurrentUser());
            var invalidBlob = RandomNumberGenerator.GetBytes(128);
            try
            {
                Assert.ThrowsExactly<DpapiNgException>(
                    () => vault.ImportProtected(
                        new SecretReference(Guid.CreateVersion7()),
                        invalidBlob));
                Assert.IsEmpty(Directory.GetFiles(root));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(invalidBlob);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
