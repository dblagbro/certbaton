namespace CertBaton.Application.Security;

public readonly record struct SecretReference
{
    public SecretReference(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "A secret reference cannot be empty.",
                nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public override string ToString() => Value.ToString("D");
}

public interface ISecretVault
{
    bool Contains(SecretReference reference);

    void Store(
        SecretReference reference,
        ReadOnlySpan<byte> secret,
        bool replace = false);

    void ImportProtected(
        SecretReference reference,
        ReadOnlySpan<byte> protectedSecret,
        bool replace = false);

    byte[] Read(SecretReference reference);

    bool Delete(SecretReference reference);
}
