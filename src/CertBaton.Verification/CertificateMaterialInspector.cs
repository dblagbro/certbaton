using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertBaton.Application.Verification;

namespace CertBaton.Verification;

public sealed class CertificateMaterialInspector : ICertificateMaterialInspector
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    public CertificateInspectionResult Inspect(
        string certificateChainPem,
        string privateKeyPem,
        string expectedHostname,
        DateTimeOffset nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateChainPem);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPem);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedHostname);

        try
        {
            using var certificate = X509Certificate2.CreateFromPem(
                certificateChainPem,
                privateKeyPem);
            var fingerprint = certificate.GetCertHashString(
                HashAlgorithmName.SHA256);
            var notBefore = new DateTimeOffset(
                certificate.NotBefore.ToUniversalTime());
            var notAfter = new DateTimeOffset(
                certificate.NotAfter.ToUniversalTime());
            var now = nowUtc.ToUniversalTime();
            if (now < notBefore || now >= notAfter)
            {
                return Failed(
                    "certificate.outside_validity",
                    fingerprint,
                    notBefore,
                    notAfter);
            }

            if (!MatchesHostname(certificate, expectedHostname))
            {
                return Failed(
                    "certificate.name_mismatch",
                    fingerprint,
                    notBefore,
                    notAfter);
            }

            if (!AllowsServerAuthentication(certificate))
            {
                return Failed(
                    "certificate.eku_mismatch",
                    fingerprint,
                    notBefore,
                    notAfter);
            }

            return new CertificateInspectionResult(
                true,
                "certificate.verified",
                fingerprint,
                notBefore,
                notAfter);
        }
        catch (CryptographicException)
        {
            return Failed("certificate.invalid_material");
        }
    }

    private static bool MatchesHostname(
        X509Certificate2 certificate,
        string expectedHostname)
    {
        var normalized = expectedHostname.Trim().TrimEnd('.');
        var dnsName = certificate.GetNameInfo(
            X509NameType.DnsName,
            forIssuer: false);
        return string.Equals(
            dnsName.TrimEnd('.'),
            normalized,
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool AllowsServerAuthentication(X509Certificate2 certificate)
    {
        var eku = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SingleOrDefault();
        return eku is null || eku.EnhancedKeyUsages
            .Cast<Oid>()
            .Any(oid => string.Equals(
                oid.Value,
                ServerAuthenticationOid,
                StringComparison.Ordinal));
    }

    private static CertificateInspectionResult Failed(
        string code,
        string? fingerprint = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null) =>
        new(false, code, fingerprint, notBefore, notAfter);
}
