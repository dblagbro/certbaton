using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CertBaton.Application.Acme;
using CertBaton.Application.Live;
using CertBaton.Application.Persistence;
using CertBaton.Application.Security;
using CertBaton.Domain.Operations;
using CertBaton.Domain.Targets;

namespace CertBaton.Service;

public sealed class VaultBackedAcmeAccountStore : IAcmeAccountStore
{
    private const int MaximumAccountKeyBytes = 64 * 1024;
    private static readonly byte[] envelopeMagic =
        "CBACME1\0"u8.ToArray();
    private static readonly UTF8Encoding strictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private readonly IProductionStore productionStore;
    private readonly ISecretVault secretVault;
    private readonly TimeProvider timeProvider;

    public VaultBackedAcmeAccountStore(
        IProductionStore productionStore,
        ISecretVault secretVault,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(productionStore);
        ArgumentNullException.ThrowIfNull(secretVault);
        ArgumentNullException.ThrowIfNull(timeProvider);
        this.productionStore = productionStore;
        this.secretVault = secretVault;
        this.timeProvider = timeProvider;
    }

    public Task<AcmeAccount?> LoadAsync(
        Uri directoryUri,
        SecretReference accountKeyReference,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!secretVault.Contains(accountKeyReference))
        {
            return Task.FromResult<AcmeAccount?>(null);
        }

        var record = productionStore.FindAcmeAccount(
            directoryUri,
            accountKeyReference.ToString());
        var protectedPayload = secretVault.Read(accountKeyReference);
        byte[]? accountKey = null;
        try
        {
            Uri accountDirectory;
            Uri accountUri;
            if (TryDecodeEnvelope(
                    protectedPayload,
                    out accountDirectory,
                    out accountUri,
                    out accountKey))
            {
                if (accountDirectory != directoryUri)
                {
                    throw new InvalidOperationException(
                        "The protected ACME account belongs to another directory.");
                }

                record = PersistAndValidateRecord(
                    accountKeyReference,
                    accountDirectory,
                    accountUri,
                    record);
            }
            else
            {
                if (HasEnvelopePrefix(protectedPayload))
                {
                    throw new InvalidDataException(
                        "The protected ACME account envelope is invalid.");
                }

                if (record?.AccountUri is null)
                {
                    return Task.FromResult<AcmeAccount?>(null);
                }

                accountDirectory = record.DirectoryUri;
                accountUri = record.AccountUri;
                accountKey = protectedPayload.ToArray();
            }

            ValidateRecord(
                record,
                accountKeyReference,
                accountDirectory,
                accountUri);
            return Task.FromResult<AcmeAccount?>(
                new AcmeAccount(
                    accountDirectory,
                    accountUri,
                    accountKey));
        }
        finally
        {
            if (accountKey is not null)
            {
                CryptographicOperations.ZeroMemory(accountKey);
            }

            CryptographicOperations.ZeroMemory(protectedPayload);
        }
    }

    public Task SaveAsync(
        AcmeAccount account,
        SecretReference accountKeyReference,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);
        cancellationToken.ThrowIfCancellationRequested();
        var accountKey = account.ExportAccountKeyPem();
        byte[]? envelope = null;
        try
        {
            envelope = EncodeEnvelope(account, accountKey);
            SaveOrVerifyEnvelope(
                accountKeyReference,
                account,
                accountKey,
                envelope);
            _ = PersistAndValidateRecord(
                accountKeyReference,
                account.DirectoryUri,
                account.AccountUri,
                productionStore.FindAcmeAccount(
                    account.DirectoryUri,
                    accountKeyReference.ToString()));

            return Task.CompletedTask;
        }
        finally
        {
            if (envelope is not null)
            {
                CryptographicOperations.ZeroMemory(envelope);
            }

            CryptographicOperations.ZeroMemory(accountKey);
        }
    }

    private void SaveOrVerifyEnvelope(
        SecretReference reference,
        AcmeAccount account,
        ReadOnlySpan<byte> accountKey,
        ReadOnlySpan<byte> envelope)
    {
        if (!secretVault.Contains(reference))
        {
            secretVault.Store(reference, envelope);
            return;
        }

        var existing = secretVault.Read(reference);
        byte[]? existingKey = null;
        try
        {
            if (TryDecodeEnvelope(
                    existing,
                    out var existingDirectory,
                    out var existingAccountUri,
                    out existingKey))
            {
                if (existingDirectory != account.DirectoryUri ||
                    existingAccountUri != account.AccountUri ||
                    !CryptographicOperations.FixedTimeEquals(
                        existingKey,
                        accountKey))
                {
                    throw new InvalidOperationException(
                        "The ACME account-key reference already protects different material.");
                }

                return;
            }

            if (HasEnvelopePrefix(existing) ||
                !CryptographicOperations.FixedTimeEquals(existing, accountKey))
            {
                throw new InvalidOperationException(
                    "The ACME account-key reference already protects different material.");
            }

            secretVault.Store(reference, envelope, replace: true);
        }
        finally
        {
            if (existingKey is not null)
            {
                CryptographicOperations.ZeroMemory(existingKey);
            }

            CryptographicOperations.ZeroMemory(existing);
        }
    }

    private AcmeAccountRecord PersistAndValidateRecord(
        SecretReference reference,
        Uri directoryUri,
        Uri accountUri,
        AcmeAccountRecord? existing)
    {
        var now = timeProvider.GetUtcNow();
        var persisted = existing ?? productionStore.CreateOrGetAcmeAccount(
            new AcmeAccountRecord(
                new AcmeAccountId(reference.Value),
                directoryUri,
                accountUri,
                contactEmail: null,
                reference.ToString(),
                AcmeAccountStatus.Valid,
                now,
                now));
        if (persisted.Status == AcmeAccountStatus.Pending)
        {
            persisted = productionStore.UpdateAcmeAccountRegistration(
                persisted.Id,
                AcmeAccountStatus.Pending,
                accountUri,
                AcmeAccountStatus.Valid,
                now);
        }

        ValidateRecord(persisted, reference, directoryUri, accountUri);
        return persisted;
    }

    private static void ValidateRecord(
        AcmeAccountRecord? record,
        SecretReference reference,
        Uri directoryUri,
        Uri accountUri)
    {
        if (record is null ||
            record.Status != AcmeAccountStatus.Valid ||
            record.AccountUri != accountUri ||
            record.DirectoryUri != directoryUri ||
            !string.Equals(
                record.KeySecretReference,
                reference.ToString(),
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The persisted ACME account does not match the protected account key.");
        }
    }

    private static byte[] EncodeEnvelope(
        AcmeAccount account,
        ReadOnlySpan<byte> accountKey)
    {
        if (accountKey.IsEmpty || accountKey.Length > MaximumAccountKeyBytes)
        {
            throw new InvalidDataException(
                "The ACME account key exceeds the protected-envelope limit.");
        }

        var directoryBytes = strictUtf8.GetBytes(account.DirectoryUri.AbsoluteUri);
        var accountUriBytes = strictUtf8.GetBytes(account.AccountUri.AbsoluteUri);
        var length = checked(
            envelopeMagic.Length +
            (3 * sizeof(int)) +
            directoryBytes.Length +
            accountUriBytes.Length +
            accountKey.Length);
        var envelope = GC.AllocateUninitializedArray<byte>(length);
        var offset = 0;
        envelopeMagic.CopyTo(envelope, offset);
        offset += envelopeMagic.Length;
        WriteLength(envelope, ref offset, directoryBytes.Length);
        WriteLength(envelope, ref offset, accountUriBytes.Length);
        WriteLength(envelope, ref offset, accountKey.Length);
        directoryBytes.CopyTo(envelope, offset);
        offset += directoryBytes.Length;
        accountUriBytes.CopyTo(envelope, offset);
        offset += accountUriBytes.Length;
        accountKey.CopyTo(envelope.AsSpan(offset));
        return envelope;
    }

    private static bool TryDecodeEnvelope(
        ReadOnlySpan<byte> envelope,
        out Uri directoryUri,
        out Uri accountUri,
        out byte[] accountKey)
    {
        directoryUri = null!;
        accountUri = null!;
        accountKey = [];
        if (!HasEnvelopePrefix(envelope) ||
            envelope.Length < envelopeMagic.Length + (3 * sizeof(int)))
        {
            return false;
        }

        try
        {
            var offset = envelopeMagic.Length;
            var directoryLength = ReadLength(envelope, ref offset, 2_048);
            var accountUriLength = ReadLength(envelope, ref offset, 2_048);
            var accountKeyLength = ReadLength(
                envelope,
                ref offset,
                MaximumAccountKeyBytes);
            if (directoryLength < 1 ||
                accountUriLength < 1 ||
                accountKeyLength < 1 ||
                checked(
                    offset +
                    directoryLength +
                    accountUriLength +
                    accountKeyLength) != envelope.Length)
            {
                return false;
            }

            var directory = strictUtf8.GetString(
                envelope.Slice(offset, directoryLength));
            offset += directoryLength;
            var accountLocation = strictUtf8.GetString(
                envelope.Slice(offset, accountUriLength));
            offset += accountUriLength;
            if (!Uri.TryCreate(
                    directory,
                    UriKind.Absolute,
                    out var parsedDirectoryUri) ||
                !Uri.TryCreate(
                    accountLocation,
                    UriKind.Absolute,
                    out var parsedAccountUri) ||
                !string.Equals(
                    parsedDirectoryUri.Scheme,
                    Uri.UriSchemeHttps,
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    parsedAccountUri.Scheme,
                    Uri.UriSchemeHttps,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            directoryUri = parsedDirectoryUri;
            accountUri = parsedAccountUri;
            accountKey = envelope.Slice(offset, accountKeyLength).ToArray();
            return true;
        }
        catch (Exception exception) when (
            exception is ArgumentException or
            DecoderFallbackException or
            OverflowException)
        {
            if (accountKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(accountKey);
                accountKey = [];
            }

            return false;
        }
    }

    private static bool HasEnvelopePrefix(ReadOnlySpan<byte> value) =>
        value.Length >= envelopeMagic.Length &&
        value[..envelopeMagic.Length].SequenceEqual(envelopeMagic);

    private static void WriteLength(
        Span<byte> destination,
        ref int offset,
        int value)
    {
        BinaryPrimitives.WriteInt32BigEndian(
            destination.Slice(offset, sizeof(int)),
            value);
        offset += sizeof(int);
    }

    private static int ReadLength(
        ReadOnlySpan<byte> source,
        ref int offset,
        int maximum)
    {
        if (offset > source.Length - sizeof(int))
        {
            return -1;
        }

        var value = BinaryPrimitives.ReadInt32BigEndian(
            source.Slice(offset, sizeof(int)));
        offset += sizeof(int);
        return value <= maximum ? value : -1;
    }
}

public sealed class VaultCertificatePrivateKeyStore : ICertificatePrivateKeyStore
{
    private readonly ISecretVault secretVault;

    public VaultCertificatePrivateKeyStore(ISecretVault secretVault)
    {
        ArgumentNullException.ThrowIfNull(secretVault);
        this.secretVault = secretVault;
    }

    public Task<SecretReference> StorePendingAsync(
        Guid operationId,
        ReadOnlyMemory<byte> privateKeyPem,
        CancellationToken cancellationToken)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException(
                "The operation ID cannot be empty.",
                nameof(operationId));
        }

        if (privateKeyPem.IsEmpty)
        {
            throw new ArgumentException(
                "The pending certificate key cannot be empty.",
                nameof(privateKeyPem));
        }

        cancellationToken.ThrowIfCancellationRequested();
        var reference = new SecretReference(operationId);
        if (!secretVault.Contains(reference))
        {
            secretVault.Store(reference, privateKeyPem.Span);
            return Task.FromResult(reference);
        }

        var existing = secretVault.Read(reference);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    existing,
                    privateKeyPem.Span))
            {
                throw new InvalidOperationException(
                    "The operation already protects a different certificate key.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(existing);
        }

        return Task.FromResult(reference);
    }
}

public sealed class ProductionIssuedCertificateStore : IIssuedCertificateStore
{
    private readonly IProductionStore productionStore;
    private readonly TimeProvider timeProvider;

    public ProductionIssuedCertificateStore(
        IProductionStore productionStore,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(productionStore);
        ArgumentNullException.ThrowIfNull(timeProvider);
        this.productionStore = productionStore;
        this.timeProvider = timeProvider;
    }

    public Task PersistIssuedAsync(
        LiveIssuedCertificateArtifact certificateArtifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificateArtifact);
        cancellationToken.ThrowIfCancellationRequested();
        var operationId = new OperationId(certificateArtifact.OperationId);
        _ = productionStore.FindOperation(operationId)
            ?? throw new KeyNotFoundException(
                "The issued certificate refers to an unknown renewal operation.");
        _ = productionStore.CreateOrGetCertificateArtifact(
            new CertificateArtifact(
                new CertificateArtifactId(certificateArtifact.OperationId),
                operationId,
                new Sha256Digest(certificateArtifact.CertificateLeafSha256),
                new Sha256Digest(certificateArtifact.PublicKeySha256),
                certificateArtifact.PrivateKeyReference.ToString(),
                certificateArtifact.NotBeforeUtc,
                certificateArtifact.NotAfterUtc,
                CertificateArtifactStatus.Issued,
                timeProvider.GetUtcNow()));
        return Task.CompletedTask;
    }
}
