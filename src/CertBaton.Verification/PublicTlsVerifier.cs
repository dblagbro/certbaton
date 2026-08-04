using System.Collections.ObjectModel;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertBaton.Application.Verification;

namespace CertBaton.Verification;

public sealed class PublicTlsVerifier : IPublicTlsVerifier
{
    private static readonly TimeSpan connectTimeout = TimeSpan.FromSeconds(10);

    public async Task<PublicTlsVerificationResult> VerifyAsync(
        PublicTlsVerificationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var addresses = await Dns.GetHostAddressesAsync(
                request.Hostname,
                cancellationToken)
            .ConfigureAwait(false);
        if (addresses.Length == 0 || addresses.Any(
                static address => !PublicAddressPolicy.IsPublic(address)))
        {
            return Failed(
                "tls.non_public_address",
                Array.AsReadOnly(addresses));
        }

        Exception? lastError = null;
        foreach (var address in addresses)
        {
            try
            {
                return await VerifyAddressAsync(
                        request,
                        address,
                        Array.AsReadOnly(addresses),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is IOException or
                SocketException or
                AuthenticationException or
                TimeoutException)
            {
                lastError = exception;
            }
        }

        return Failed(
            lastError is AuthenticationException
                ? "tls.authentication_failed"
                : "tls.connection_failed",
            Array.AsReadOnly(addresses));
    }

    private static async Task<PublicTlsVerificationResult> VerifyAddressAsync(
        PublicTlsVerificationRequest request,
        IPAddress address,
        ReadOnlyCollection<IPAddress> addresses,
        CancellationToken cancellationToken)
    {
        using var client = new TcpClient(address.AddressFamily);
        await client.ConnectAsync(address, request.Port, cancellationToken)
            .AsTask()
            .WaitAsync(connectTimeout, cancellationToken)
            .ConfigureAwait(false);

        SslPolicyErrors observedErrors = SslPolicyErrors.None;
        string? observedFingerprint = null;
        DateTimeOffset? notBefore = null;
        DateTimeOffset? notAfter = null;
        using var ssl = new SslStream(
            client.GetStream(),
            leaveInnerStreamOpen: false,
            (_, certificate, _, policyErrors) =>
            {
                observedErrors = policyErrors;
                if (certificate is null)
                {
                    return false;
                }

                using var leaf = X509CertificateLoader.LoadCertificate(
                    certificate.GetRawCertData());
                observedFingerprint = leaf.GetCertHashString(
                    HashAlgorithmName.SHA256);
                notBefore = leaf.NotBefore.ToUniversalTime();
                notAfter = leaf.NotAfter.ToUniversalTime();
                var fingerprintMatches = string.Equals(
                    observedFingerprint,
                    request.ExpectedLeafSha256,
                    StringComparison.Ordinal);
                var hostnameMatches =
                    (policyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                var chainTrusted =
                    (policyErrors & SslPolicyErrors.RemoteCertificateChainErrors) == 0;
                return fingerprintMatches &&
                    hostnameMatches &&
                    (request.TrustPolicy == TlsTrustPolicy.ExpectedLeaf ||
                     chainTrusted);
            });

        await ssl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = request.Hostname,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.Online,
                },
                cancellationToken)
            .ConfigureAwait(false);

        var hostnameMatched =
            (observedErrors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
        var chainTrusted =
            (observedErrors & SslPolicyErrors.RemoteCertificateChainErrors) == 0;
        var success = string.Equals(
                observedFingerprint,
                request.ExpectedLeafSha256,
                StringComparison.Ordinal) &&
            hostnameMatched &&
            (request.TrustPolicy == TlsTrustPolicy.ExpectedLeaf || chainTrusted);
        return new PublicTlsVerificationResult(
            success,
            success ? "tls.verified" : "tls.mismatch",
            observedFingerprint,
            notBefore,
            notAfter,
            hostnameMatched,
            chainTrusted,
            addresses);
    }

    private static PublicTlsVerificationResult Failed(
        string code,
        IReadOnlyList<IPAddress> addresses) =>
        new(
            false,
            code,
            null,
            null,
            null,
            false,
            false,
            addresses);
}
