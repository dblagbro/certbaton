using System.Collections.ObjectModel;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertBaton.Application.Verification;

namespace CertBaton.Verification;

public sealed class PublicHttp01Verifier : IPublicHttp01Verifier, IDisposable
{
    private readonly IPinnedHttp01Transport transport;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> resolver;

    public PublicHttp01Verifier()
        : this(
            new PinnedHttp01Transport(),
            static (hostname, cancellationToken) =>
                Dns.GetHostAddressesAsync(hostname, cancellationToken))
    {
    }

    internal PublicHttp01Verifier(
        IPinnedHttp01Transport transport,
        Func<string, CancellationToken, Task<IPAddress[]>> resolver)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(resolver);
        this.transport = transport;
        this.resolver = resolver;
    }

    public async Task<Http01VerificationResult> VerifyAsync(
        Http01VerificationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var currentUri = request.ChallengeUri;
        var addresses = await ResolvePublicAddressesAsync(
                currentUri.DnsSafeHost,
                cancellationToken)
            .ConfigureAwait(false);

        for (var redirectCount = 0;
             redirectCount <= request.MaximumRedirects;
             redirectCount++)
        {
            var response = await transport
                .SendAsync(currentUri, addresses, cancellationToken)
                .ConfigureAwait(false);

            if (IsRedirect(response.StatusCode))
            {
                if (redirectCount == request.MaximumRedirects ||
                    response.Location is null)
                {
                    return Failed(
                        "http01.redirect_limit",
                        currentUri,
                        response.StatusCode,
                        redirectCount,
                        addresses);
                }

                var nextUri = response.Location.IsAbsoluteUri
                    ? response.Location
                    : new Uri(currentUri, response.Location);
                if (!IsAllowedRedirect(nextUri))
                {
                    return Failed(
                        "http01.redirect_unsupported",
                        nextUri,
                        response.StatusCode,
                        redirectCount + 1,
                        addresses);
                }

                addresses = await ResolvePublicAddressesAsync(
                        nextUri.DnsSafeHost,
                        cancellationToken)
                    .ConfigureAwait(false);
                currentUri = nextUri;
                continue;
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                return Failed(
                    "http01.status_mismatch",
                    currentUri,
                    response.StatusCode,
                    redirectCount,
                    addresses);
            }

            var matches = string.Equals(
                response.Content,
                request.ExpectedKeyAuthorization,
                StringComparison.Ordinal);
            return new Http01VerificationResult(
                matches,
                matches ? "http01.verified" : "http01.content_mismatch",
                currentUri,
                response.StatusCode,
                redirectCount,
                addresses);
        }

        throw new InvalidOperationException(
            "The HTTP-01 redirect loop exited unexpectedly.");
    }

    public void Dispose()
    {
        if (transport is IDisposable disposableTransport)
        {
            disposableTransport.Dispose();
        }
    }

    private async Task<ReadOnlyCollection<IPAddress>> ResolvePublicAddressesAsync(
        string hostname,
        CancellationToken cancellationToken)
    {
        var resolvedAddresses = await resolver(hostname, cancellationToken)
            .ConfigureAwait(false);
        var addresses = resolvedAddresses
            .Select(CloneAddress)
            .ToArray();
        if (addresses.Length == 0 || addresses.Any(
                static address => !PublicAddressPolicy.IsPublic(address)))
        {
            throw new InvalidOperationException(
                "Public verification refused a hostname with a non-public address.");
        }

        return Array.AsReadOnly(addresses);
    }

    private static IPAddress CloneAddress(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPAddress(address.GetAddressBytes(), address.ScopeId)
            : new IPAddress(address.GetAddressBytes());

    private static bool IsRedirect(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.MovedPermanently or
            HttpStatusCode.Redirect or
            HttpStatusCode.RedirectMethod or
            HttpStatusCode.TemporaryRedirect or
            HttpStatusCode.PermanentRedirect;

    private static bool IsAllowedRedirect(Uri uri) =>
        uri.IsAbsoluteUri &&
        ((string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) &&
          uri.Port == 80) ||
         (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
          uri.Port == 443));

    private static Http01VerificationResult Failed(
        string code,
        Uri finalUri,
        HttpStatusCode? statusCode,
        int redirectCount,
        IReadOnlyList<IPAddress> addresses) =>
        new(
            false,
            code,
            finalUri,
            statusCode,
            redirectCount,
            addresses);
}

internal interface IPinnedHttp01Transport
{
    Task<PinnedHttp01Response> SendAsync(
        Uri requestUri,
        IReadOnlyList<IPAddress> addresses,
        CancellationToken cancellationToken);
}

internal sealed record PinnedHttp01Response(
    HttpStatusCode StatusCode,
    Uri? Location,
    string? Content = null);

internal sealed class PinnedHttp01Transport : IPinnedHttp01Transport
{
    private const int MaximumResponseBytes = 4096;
    private static readonly TimeSpan connectTimeout = TimeSpan.FromSeconds(10);
    private readonly PinnedAddressConnector connector;

    public PinnedHttp01Transport()
        : this(ConnectSocketAsync)
    {
    }

    internal PinnedHttp01Transport(PinnedAddressConnector connector)
    {
        ArgumentNullException.ThrowIfNull(connector);
        this.connector = connector;
    }

    public async Task<PinnedHttp01Response> SendAsync(
        Uri requestUri,
        IReadOnlyList<IPAddress> addresses,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestUri);
        ArgumentNullException.ThrowIfNull(addresses);
        if (!IsSupportedEndpoint(requestUri) ||
            addresses.Count == 0 ||
            addresses.Any(static address => !PublicAddressPolicy.IsPublic(address)))
        {
            throw new InvalidOperationException(
                "The pinned HTTP transport refused an unsupported endpoint.");
        }

        using var handler = CreateHandler(
            (context, token) =>
                ConnectPinnedAsync(
                    context.DnsEndPoint,
                    requestUri,
                    addresses,
                    token));
        using var client = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
        using var message = new HttpRequestMessage(HttpMethod.Get, requestUri);
        message.Headers.UserAgent.ParseAdd("CertBaton-Preflight/0.1");
        using var response = await client
            .SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);

        var content = response.StatusCode == HttpStatusCode.OK
            ? await ReadBoundedStringAsync(
                    response.Content,
                    cancellationToken)
                .ConfigureAwait(false)
            : null;
        return new PinnedHttp01Response(
            response.StatusCode,
            response.Headers.Location,
            content);
    }

    internal static SocketsHttpHandler CreateHandler(
        Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>>
            connectCallback) =>
        new()
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectCallback = connectCallback,
            ConnectTimeout = connectTimeout,
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateChainPolicy = new X509ChainPolicy
                {
                    DisableCertificateDownloads = true,
                    RevocationMode = X509RevocationMode.NoCheck,
                    TrustMode = X509ChainTrustMode.System,
                },
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            },
            UseCookies = false,
            UseProxy = false,
        };

    private async ValueTask<Stream> ConnectPinnedAsync(
        DnsEndPoint endpoint,
        Uri requestUri,
        IReadOnlyList<IPAddress> addresses,
        CancellationToken cancellationToken)
    {
        if (endpoint.Port != requestUri.Port ||
            !string.Equals(
                endpoint.Host.TrimEnd('.'),
                requestUri.DnsSafeHost.TrimEnd('.'),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new HttpRequestException(
                "The HTTP handler requested a connection outside the pinned endpoint.");
        }

        Exception? lastError = null;
        foreach (var address in addresses)
        {
            if (!PublicAddressPolicy.IsPublic(address))
            {
                throw new InvalidOperationException(
                    "The HTTP handler refused a non-public pinned address.");
            }

            try
            {
                return await connector(
                        address,
                        endpoint.Port,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is IOException or SocketException)
            {
                lastError = exception;
            }
        }

        throw new HttpRequestException(
            "No validated address accepted the HTTP connection.",
            lastError);
    }

    private static async ValueTask<Stream> ConnectSocketAsync(
        IPAddress address,
        int port,
        CancellationToken cancellationToken)
    {
        var socket = new Socket(
            address.AddressFamily,
            SocketType.Stream,
            ProtocolType.Tcp);
        try
        {
            await socket
                .ConnectAsync(new IPEndPoint(address, port), cancellationToken)
                .ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static async Task<string> ReadBoundedStringAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > MaximumResponseBytes)
        {
            throw new InvalidDataException(
                "The HTTP-01 response exceeded the verification limit.");
        }

        await using var stream = await content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[512];
        while (true)
        {
            var read = await stream
                .ReadAsync(chunk, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (buffer.Length + read > MaximumResponseBytes)
            {
                throw new InvalidDataException(
                    "The HTTP-01 response exceeded the verification limit.");
            }

            buffer.Write(chunk, 0, read);
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static bool IsSupportedEndpoint(Uri uri) =>
        uri.IsAbsoluteUri &&
        ((string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) &&
          uri.Port == 80) ||
         (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
          uri.Port == 443));
}

internal delegate ValueTask<Stream> PinnedAddressConnector(
    IPAddress address,
    int port,
    CancellationToken cancellationToken);
