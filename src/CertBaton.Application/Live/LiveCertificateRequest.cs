using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertBaton.Application.Live;

internal sealed class LiveCertificateRequest : IDisposable
{
    private byte[]? privateKeyPem;

    private LiveCertificateRequest(byte[] csrDer, byte[] privateKeyPem)
    {
        CertificateSigningRequestDer = csrDer;
        this.privateKeyPem = privateKeyPem;
    }

    public byte[] CertificateSigningRequestDer { get; }

    public ReadOnlyMemory<byte> PrivateKeyPem => GetPrivateKeyPem();

    public static LiveCertificateRequest Create(
        IReadOnlyList<string> dnsNames)
    {
        ArgumentNullException.ThrowIfNull(dnsNames);
        if (dnsNames.Count == 0)
        {
            throw new ArgumentException(
                "At least one DNS name is required.",
                nameof(dnsNames));
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            $"CN={dnsNames[0]}",
            key,
            HashAlgorithmName.SHA256);

        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
        foreach (var dnsName in dnsNames)
        {
            subjectAlternativeNames.AddDnsName(dnsName);
        }

        request.CertificateExtensions.Add(
            subjectAlternativeNames.Build(critical: false));
        var enhancedKeyUsages = new OidCollection
        {
            new Oid("1.3.6.1.5.5.7.3.1", "TLS Web Server Authentication"),
        };
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                enhancedKeyUsages,
                critical: false));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));

        var privateKeyDer = key.ExportPkcs8PrivateKey();
        try
        {
            return new LiveCertificateRequest(
                request.CreateSigningRequest(),
                EncodePem("PRIVATE KEY", privateKeyDer));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyDer);
        }
    }

    public string ExportPrivateKeyPemString() =>
        Encoding.ASCII.GetString(GetPrivateKeyPem());

    public Stream OpenPrivateKeyPemStream() =>
        new MemoryStream(GetPrivateKeyPem(), writable: false);

    public void Dispose()
    {
        var key = Interlocked.Exchange(ref privateKeyPem, null);
        if (key is not null)
        {
            CryptographicOperations.ZeroMemory(key);
        }

        CryptographicOperations.ZeroMemory(CertificateSigningRequestDer);
    }

    private byte[] GetPrivateKeyPem() =>
        privateKeyPem ??
        throw new ObjectDisposedException(nameof(LiveCertificateRequest));

    private static byte[] EncodePem(
        string label,
        ReadOnlySpan<byte> der)
    {
        var characters = PemEncoding.Write(label, der);
        try
        {
            return Encoding.ASCII.GetBytes(characters);
        }
        finally
        {
            characters.AsSpan().Clear();
        }
    }
}
