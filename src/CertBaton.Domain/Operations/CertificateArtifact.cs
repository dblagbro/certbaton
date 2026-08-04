using System.Globalization;

namespace CertBaton.Domain.Operations;

public readonly record struct CertificateArtifactId
{
    public CertificateArtifactId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "A certificate artifact identifier cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static CertificateArtifactId Create() => new(Guid.CreateVersion7());

    public override string ToString() =>
        Value.ToString("D", CultureInfo.InvariantCulture);
}

public readonly record struct Sha256Digest
{
    public Sha256Digest(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != 64 || !value.All(char.IsAsciiHexDigit))
        {
            throw new ArgumentException(
                "A SHA-256 digest must contain exactly 64 hexadecimal characters.",
                nameof(value));
        }

        Value = value.ToUpperInvariant();
    }

    public string Value { get; }

    public override string ToString() => Value;
}

public enum CertificateArtifactStatus
{
    Issued = 0,
    Deployed = 1,
    Revoked = 2,
}

public sealed record CertificateArtifact
{
    public CertificateArtifact(
        CertificateArtifactId id,
        OperationId operationId,
        Sha256Digest certificateSha256,
        Sha256Digest publicKeySha256,
        string privateKeySecretReference,
        DateTimeOffset notBeforeUtc,
        DateTimeOffset notAfterUtc,
        CertificateArtifactStatus status,
        DateTimeOffset createdAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A certificate artifact identifier cannot be empty.",
                nameof(id));
        }

        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation identifier cannot be empty.",
                nameof(operationId));
        }

        if (string.IsNullOrEmpty(certificateSha256.Value))
        {
            throw new ArgumentException(
                "A certificate SHA-256 digest is required.",
                nameof(certificateSha256));
        }

        if (string.IsNullOrEmpty(publicKeySha256.Value))
        {
            throw new ArgumentException(
                "A public-key SHA-256 digest is required.",
                nameof(publicKeySha256));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeySecretReference);
        if (privateKeySecretReference.Length > 200 ||
            !string.Equals(
                privateKeySecretReference,
                privateKeySecretReference.Trim(),
                StringComparison.Ordinal) ||
            privateKeySecretReference.Any(char.IsControl))
        {
            throw new ArgumentException(
                "The private-key secret reference is invalid.",
                nameof(privateKeySecretReference));
        }

        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        Id = id;
        OperationId = operationId;
        CertificateSha256 = certificateSha256;
        PublicKeySha256 = publicKeySha256;
        PrivateKeySecretReference = privateKeySecretReference;
        NotBeforeUtc = notBeforeUtc.ToUniversalTime();
        NotAfterUtc = notAfterUtc.ToUniversalTime();
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        if (NotAfterUtc <= NotBeforeUtc)
        {
            throw new ArgumentException(
                "The certificate not-after timestamp must follow not-before.",
                nameof(notAfterUtc));
        }

        Status = status;
    }

    public CertificateArtifactId Id { get; }

    public OperationId OperationId { get; }

    public Sha256Digest CertificateSha256 { get; }

    public Sha256Digest PublicKeySha256 { get; }

    public string PrivateKeySecretReference { get; }

    public DateTimeOffset NotBeforeUtc { get; }

    public DateTimeOffset NotAfterUtc { get; }

    public CertificateArtifactStatus Status { get; }

    public DateTimeOffset CreatedAtUtc { get; }
}
