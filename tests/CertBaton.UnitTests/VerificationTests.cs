using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertBaton.Application.Verification;
using CertBaton.Verification;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class VerificationTests
{
    private static readonly Func<string, CancellationToken, Task<IPAddress[]>>
        publicResolver = static (_, _) =>
            Task.FromResult<IPAddress[]>(
            [
                IPAddress.Parse("8.8.8.8"),
            ]);

    [TestMethod]
    public async Task HttpVerifierRequiresExactChallengeContent()
    {
        var transport = new ScriptedPinnedTransport(
            new PinnedHttp01Response(
                HttpStatusCode.OK,
                null,
                "token.thumbprint"));
        using var verifier = new PublicHttp01Verifier(
            transport,
            publicResolver);

        var result = await verifier.VerifyAsync(
            new Http01VerificationRequest(
                new Uri(
                    "http://example.test/.well-known/acme-challenge/token"),
                "token.thumbprint"),
            CancellationToken.None);

        Assert.IsTrue(result.Success);
        Assert.AreEqual("http01.verified", result.Code);
    }

    [TestMethod]
    public async Task HttpVerifierRejectsTrailingContent()
    {
        var transport = new ScriptedPinnedTransport(
            new PinnedHttp01Response(
                HttpStatusCode.OK,
                null,
                "token.thumbprint\n"));
        using var verifier = new PublicHttp01Verifier(
            transport,
            publicResolver);

        var result = await verifier.VerifyAsync(
            new Http01VerificationRequest(
                new Uri(
                    "http://example.test/.well-known/acme-challenge/token"),
                "token.thumbprint"),
            CancellationToken.None);

        Assert.IsFalse(result.Success);
        Assert.AreEqual("http01.content_mismatch", result.Code);
    }

    [TestMethod]
    public async Task HttpVerifierRejectsPrivateResolutionBeforeRequest()
    {
        var transport = new ScriptedPinnedTransport(
            new PinnedHttp01Response(
                HttpStatusCode.OK,
                null,
                "token.thumbprint"));
        using var verifier = new PublicHttp01Verifier(
            transport,
            static (_, _) =>
                Task.FromResult<IPAddress[]>(
                [
                    IPAddress.Loopback,
                ]));

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => verifier.VerifyAsync(
                new Http01VerificationRequest(
                    new Uri(
                        "http://example.test/.well-known/acme-challenge/token"),
                    "token.thumbprint"),
                CancellationToken.None));
        Assert.AreEqual(0, transport.Requests.Count);
    }

    [TestMethod]
    public async Task HttpVerifierPinsResolvedAddressSnapshotForEachRedirectHop()
    {
        var firstAddress = IPAddress.Parse("8.8.8.8");
        var secondAddress = IPAddress.Parse("1.1.1.1");
        var transport = new ScriptedPinnedTransport(
            new PinnedHttp01Response(
                HttpStatusCode.Redirect,
                new Uri(
                    "https://redirect.example.test/.well-known/acme-challenge/token")),
            new PinnedHttp01Response(
                HttpStatusCode.OK,
                null,
                "token.thumbprint"));
        using var verifier = new PublicHttp01Verifier(
            transport,
            (hostname, _) => Task.FromResult(
                string.Equals(
                    hostname,
                    "redirect.example.test",
                    StringComparison.Ordinal)
                    ? new[] { secondAddress }
                    : new[] { firstAddress }));

        var result = await verifier.VerifyAsync(
            new Http01VerificationRequest(
                new Uri(
                    "http://origin.example.test/.well-known/acme-challenge/token"),
                "token.thumbprint"),
            CancellationToken.None);

        Assert.IsTrue(result.Success);
        Assert.AreEqual(2, transport.Requests.Count);
        CollectionAssert.AreEqual(
            new[] { firstAddress },
            transport.Requests[0].Addresses.ToArray());
        CollectionAssert.AreEqual(
            new[] { secondAddress },
            transport.Requests[1].Addresses.ToArray());
        CollectionAssert.AreEqual(
            new[] { secondAddress },
            result.ResolvedAddresses.ToArray());
    }

    [TestMethod]
    public async Task HttpVerifierRefusesRedirectThatResolvesToPrivateAddress()
    {
        var transport = new ScriptedPinnedTransport(
            new PinnedHttp01Response(
                HttpStatusCode.Redirect,
                new Uri(
                    "http://private.example.test/.well-known/acme-challenge/token")));
        using var verifier = new PublicHttp01Verifier(
            transport,
            (hostname, _) => Task.FromResult<IPAddress[]>(
            [
                string.Equals(
                    hostname,
                    "private.example.test",
                    StringComparison.Ordinal)
                    ? IPAddress.Parse("192.168.1.10")
                    : IPAddress.Parse("8.8.8.8"),
            ]));

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => verifier.VerifyAsync(
                new Http01VerificationRequest(
                    new Uri(
                        "http://origin.example.test/.well-known/acme-challenge/token"),
                    "token.thumbprint"),
                CancellationToken.None));
        Assert.AreEqual(1, transport.Requests.Count);
    }

    [TestMethod]
    public async Task HttpVerifierRefusesPrivateDnsRebindingBeforeRedirectRequest()
    {
        var resolutionCount = 0;
        var transport = new ScriptedPinnedTransport(
            new PinnedHttp01Response(
                HttpStatusCode.Redirect,
                new Uri(
                    "/.well-known/acme-challenge/redirected-token",
                    UriKind.Relative)));
        using var verifier = new PublicHttp01Verifier(
            transport,
            (_, _) => Task.FromResult<IPAddress[]>(
            [
                Interlocked.Increment(ref resolutionCount) == 1
                    ? IPAddress.Parse("8.8.8.8")
                    : IPAddress.Parse("127.0.0.1"),
            ]));

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => verifier.VerifyAsync(
                new Http01VerificationRequest(
                    new Uri(
                        "http://rebind.example.test/.well-known/acme-challenge/token"),
                    "token.thumbprint"),
                CancellationToken.None));
        Assert.AreEqual(2, resolutionCount);
        Assert.AreEqual(1, transport.Requests.Count);
        CollectionAssert.AreEqual(
            new[] { IPAddress.Parse("8.8.8.8") },
            transport.Requests[0].Addresses.ToArray());
    }

    [TestMethod]
    [DataRow("ftp://redirect.example.test/.well-known/acme-challenge/token")]
    [DataRow("http://redirect.example.test:8080/.well-known/acme-challenge/token")]
    [DataRow("https://redirect.example.test:8443/.well-known/acme-challenge/token")]
    public async Task HttpVerifierRefusesUnsupportedRedirectEndpoints(
        string location)
    {
        var transport = new ScriptedPinnedTransport(
            new PinnedHttp01Response(
                HttpStatusCode.Redirect,
                new Uri(location)));
        using var verifier = new PublicHttp01Verifier(
            transport,
            publicResolver);

        var result = await verifier.VerifyAsync(
            new Http01VerificationRequest(
                new Uri(
                    "http://origin.example.test/.well-known/acme-challenge/token"),
                "token.thumbprint"),
            CancellationToken.None);

        Assert.IsFalse(result.Success);
        Assert.AreEqual("http01.redirect_unsupported", result.Code);
        Assert.AreEqual(1, transport.Requests.Count);
    }

    [TestMethod]
    public async Task HttpVerifierAllowsExactlyTenRedirectsAndRejectsTheNext()
    {
        var redirect = new PinnedHttp01Response(
            HttpStatusCode.Redirect,
            new Uri(
                "/.well-known/acme-challenge/redirected-token",
                UriKind.Relative));
        var allowedTransport = new ScriptedPinnedTransport(
            Enumerable.Repeat(redirect, 10)
                .Append(
                    new PinnedHttp01Response(
                        HttpStatusCode.OK,
                        null,
                        "token.thumbprint"))
                .ToArray());
        using var allowedVerifier = new PublicHttp01Verifier(
            allowedTransport,
            publicResolver);

        var allowed = await allowedVerifier.VerifyAsync(
            new Http01VerificationRequest(
                new Uri(
                    "http://origin.example.test/.well-known/acme-challenge/token"),
                "token.thumbprint"),
            CancellationToken.None);

        Assert.IsTrue(allowed.Success);
        Assert.AreEqual(10, allowed.RedirectCount);
        Assert.AreEqual(11, allowedTransport.Requests.Count);

        var refusedTransport = new ScriptedPinnedTransport(
            Enumerable.Repeat(redirect, 11).ToArray());
        using var refusedVerifier = new PublicHttp01Verifier(
            refusedTransport,
            publicResolver);

        var refused = await refusedVerifier.VerifyAsync(
            new Http01VerificationRequest(
                new Uri(
                    "http://origin.example.test/.well-known/acme-challenge/token"),
                "token.thumbprint"),
            CancellationToken.None);

        Assert.IsFalse(refused.Success);
        Assert.AreEqual("http01.redirect_limit", refused.Code);
        Assert.AreEqual(10, refused.RedirectCount);
        Assert.AreEqual(11, refusedTransport.Requests.Count);
    }

    [TestMethod]
    public async Task HttpVerifierPropagatesDnsCancellationBeforeTransport()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var transport = new ScriptedPinnedTransport();
        using var verifier = new PublicHttp01Verifier(
            transport,
            (_, token) => Task.FromCanceled<IPAddress[]>(token));

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => verifier.VerifyAsync(
                new Http01VerificationRequest(
                    new Uri(
                        "http://origin.example.test/.well-known/acme-challenge/token"),
                    "token.thumbprint"),
                cancellation.Token));
        Assert.AreEqual(0, transport.Requests.Count);
    }

    [TestMethod]
    public async Task HttpVerifierRefusesMixedMappedAndTranslatedPrivateResolutions()
    {
        var refusedAddressSets = new[]
        {
            new[]
            {
                IPAddress.Parse("8.8.8.8"),
                IPAddress.Parse("10.0.0.1"),
            },
            new[]
            {
                IPAddress.Parse("::ffff:127.0.0.1"),
            },
            new[]
            {
                IPAddress.Parse("::ffff:169.254.169.254"),
            },
            new[]
            {
                IPAddress.Parse("::7f00:1"),
            },
            new[]
            {
                IPAddress.Parse("::ffff:0:7f00:1"),
            },
            new[]
            {
                IPAddress.Parse("64:ff9b::7f00:1"),
            },
            new[]
            {
                IPAddress.Parse("64:ff9b::a9fe:a9fe"),
            },
            new[]
            {
                IPAddress.Parse("64:ff9b:1::a9fe:a9fe"),
            },
        };

        foreach (var addresses in refusedAddressSets)
        {
            var transport = new ScriptedPinnedTransport(
                new PinnedHttp01Response(
                    HttpStatusCode.OK,
                    null,
                    "token.thumbprint"));
            using var verifier = new PublicHttp01Verifier(
                transport,
                (_, _) => Task.FromResult(addresses));

            await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                () => verifier.VerifyAsync(
                    new Http01VerificationRequest(
                        new Uri(
                            "http://example.test/.well-known/acme-challenge/token"),
                        "token.thumbprint"),
                    CancellationToken.None));
            Assert.AreEqual(0, transport.Requests.Count);
        }
    }

    [TestMethod]
    public void PublicAddressPolicyUsesFailClosedIpv4AndIpv6Boundaries()
    {
        var cases = new (string Address, bool Expected)[]
        {
            ("8.8.8.8", true),
            ("192.88.98.255", true),
            ("192.88.99.0", false),
            ("192.88.99.2", false),
            ("192.88.99.255", false),
            ("192.88.100.0", true),
            ("::7f00:1", false),
            ("::ffff:0:7f00:1", false),
            ("64:ff9b::7f00:1", false),
            ("64:ff9b::a9fe:a9fe", false),
            ("64:ff9b:1::a9fe:a9fe", false),
            ("100::1", false),
            ("100:0:0:1::1", false),
            ("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2000::1", true),
            ("2001::1", false),
            ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:200::1", true),
            ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:db8::1", false),
            ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:db9::1", true),
            ("2002::1", false),
            ("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2003::1", true),
            ("3fff::1", false),
            ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("3fff:1000::1", true),
            ("4000::1", false),
            ("5f00::1", false),
            ("fc00::1", false),
            ("fe00::1", false),
            ("fe80::1", false),
            ("ff00::1", false),
            ("2001:4860:4860::8888", true),
            ("2606:4700:4700::1111", true),
        };

        foreach (var testCase in cases)
        {
            Assert.AreEqual(
                testCase.Expected,
                PublicAddressPolicy.IsPublic(
                    IPAddress.Parse(testCase.Address)),
                $"Unexpected policy result for {testCase.Address}.");
        }

        var globalWithScope = new IPAddress(
            IPAddress.Parse("2001:4860:4860::8888").GetAddressBytes(),
            7);
        Assert.IsFalse(PublicAddressPolicy.IsPublic(globalWithScope));
    }

    [TestMethod]
    public void PinnedTransportHandlerDisablesAlternateNetworkPaths()
    {
        using var handler = PinnedHttp01Transport.CreateHandler(
            static (_, _) => ValueTask.FromException<Stream>(
                new NotSupportedException()));

        Assert.IsFalse(handler.AllowAutoRedirect);
        Assert.AreEqual(
            DecompressionMethods.None,
            handler.AutomaticDecompression);
        Assert.IsFalse(handler.UseCookies);
        Assert.IsFalse(handler.UseProxy);
        Assert.IsNotNull(handler.ConnectCallback);
        Assert.IsNotNull(handler.SslOptions);
        Assert.IsNull(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.AreEqual(
            X509RevocationMode.NoCheck,
            handler.SslOptions.CertificateRevocationCheckMode);
        Assert.IsNotNull(handler.SslOptions.CertificateChainPolicy);
        Assert.IsTrue(
            handler.SslOptions.CertificateChainPolicy.DisableCertificateDownloads);
        Assert.AreEqual(
            X509RevocationMode.NoCheck,
            handler.SslOptions.CertificateChainPolicy.RevocationMode);
        Assert.AreEqual(
            X509ChainTrustMode.System,
            handler.SslOptions.CertificateChainPolicy.TrustMode);
    }

    [TestMethod]
    public async Task PinnedTransportConnectsToValidatedAddressWithoutResolvingHostname()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = ServeHttpResponseAsync(listener, timeout.Token);
        var connectedAddresses = new List<IPAddress>();
        var transport = new PinnedHttp01Transport(
            async (address, _, cancellationToken) =>
            {
                connectedAddresses.Add(address);
                var socket = new Socket(
                    AddressFamily.InterNetwork,
                    SocketType.Stream,
                    ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(
                            (IPEndPoint)listener.LocalEndpoint,
                            cancellationToken)
                        .ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            });
        var pinnedAddress = IPAddress.Parse("8.8.8.8");

        var response = await transport.SendAsync(
            new Uri(
                "http://hostname-that-must-not-be-resolved.invalid/.well-known/acme-challenge/token"),
            new[] { pinnedAddress },
            timeout.Token);
        await serverTask.ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("token.thumbprint", response.Content);
        CollectionAssert.AreEqual(
            new[] { pinnedAddress },
            connectedAddresses);
    }

    [TestMethod]
    [Timeout(10_000)]
    public async Task PinnedTransportPropagatesConnectCancellation()
    {
        var connectorEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new PinnedHttp01Transport(
            async (_, _, cancellationToken) =>
            {
                connectorEntered.TrySetResult();
                await Task.Delay(
                        Timeout.InfiniteTimeSpan,
                        cancellationToken)
                    .ConfigureAwait(false);
                return Stream.Null;
            });
        using var cancellation = new CancellationTokenSource();

        var sendTask = transport.SendAsync(
            new Uri(
                "http://hostname-that-must-not-be-resolved.invalid/.well-known/acme-challenge/token"),
            new[] { IPAddress.Parse("8.8.8.8") },
            cancellation.Token);
        await connectorEntered.Task
            .WaitAsync(TimeSpan.FromSeconds(5))
            .ConfigureAwait(false);
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => sendTask);
    }

    [TestMethod]
    [Timeout(10_000)]
    public async Task PinnedTransportPropagatesCancellationFromStalledBody()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var headersSent = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseServer = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = ServeRawHttpResponseAsync(
            listener,
            "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n",
            headersSent,
            releaseServer.Task);
        var transport = CreateLoopbackTransport(listener);
        using var cancellation = new CancellationTokenSource();

        try
        {
            var sendTask = transport.SendAsync(
                new Uri(
                    "http://hostname-that-must-not-be-resolved.invalid/.well-known/acme-challenge/token"),
                new[] { IPAddress.Parse("8.8.8.8") },
                cancellation.Token);
            await headersSent.Task
                .WaitAsync(TimeSpan.FromSeconds(5))
                .ConfigureAwait(false);
            cancellation.Cancel();

            await Assert.ThrowsAsync<OperationCanceledException>(() => sendTask);
        }
        finally
        {
            releaseServer.TrySetResult();
            await serverTask
                .WaitAsync(TimeSpan.FromSeconds(5))
                .ConfigureAwait(false);
        }
    }

    [TestMethod]
    [Timeout(10_000)]
    public async Task PinnedTransportRejectsFixedAndChunkedOversizeBodies()
    {
        var oversizedBody = new string('a', 4097);
        var responses = new[]
        {
            "HTTP/1.1 200 OK\r\nContent-Length: 4097\r\nConnection: close\r\n\r\n",
            $"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1001\r\n{oversizedBody}\r\n0\r\n\r\n",
        };

        foreach (var response in responses)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var serverTask = ServeRawHttpResponseAsync(listener, response);
            var transport = CreateLoopbackTransport(listener);

            await Assert.ThrowsExactlyAsync<InvalidDataException>(
                () => transport.SendAsync(
                    new Uri(
                        "http://hostname-that-must-not-be-resolved.invalid/.well-known/acme-challenge/token"),
                    new[] { IPAddress.Parse("8.8.8.8") },
                    CancellationToken.None));
            await serverTask
                .WaitAsync(TimeSpan.FromSeconds(5))
                .ConfigureAwait(false);
        }
    }

    [TestMethod]
    public void CertificateInspectorVerifiesNameValidityEkuAndKeyPair()
    {
        var now = new DateTimeOffset(
            2026,
            7,
            31,
            12,
            0,
            0,
            TimeSpan.Zero);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=www2.example.test",
            key,
            HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("www2.example.test");
        request.CertificateExtensions.Add(san.Build());
        var usages = new OidCollection
        {
            new("1.3.6.1.5.5.7.3.1"),
        };
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(usages, critical: false));
        using var certificate = request.CreateSelfSigned(
            now.AddDays(-1),
            now.AddDays(30));
        var inspector = new CertificateMaterialInspector();

        var result = inspector.Inspect(
            certificate.ExportCertificatePem(),
            key.ExportPkcs8PrivateKeyPem(),
            "www2.example.test",
            now);

        Assert.IsTrue(result.Success);
        Assert.AreEqual("certificate.verified", result.Code);
        Assert.AreEqual(64, result.LeafSha256?.Length);
    }

    [TestMethod]
    public void CertificateInspectorRejectsMismatchedPrivateKey()
    {
        var now = DateTimeOffset.UtcNow;
        using var certificateKey = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=example.test",
            certificateKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("example.test");
        request.CertificateExtensions.Add(san.Build());
        using var certificate = request.CreateSelfSigned(
            now.AddDays(-1),
            now.AddDays(1));
        using var differentKey = RSA.Create(2048);
        var inspector = new CertificateMaterialInspector();

        var result = inspector.Inspect(
            certificate.ExportCertificatePem(),
            differentKey.ExportPkcs8PrivateKeyPem(),
            "example.test",
            now);

        Assert.IsFalse(result.Success);
        Assert.AreEqual("certificate.invalid_material", result.Code);
    }

    private static async Task ServeHttpResponseAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var socket = await listener
            .AcceptSocketAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        var requestBuffer = new byte[4096];
        var received = 0;
        while (received < requestBuffer.Length)
        {
            var read = await stream
                .ReadAsync(
                    requestBuffer.AsMemory(received),
                    cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("The test HTTP request ended early.");
            }

            received += read;
            if (Encoding.ASCII
                .GetString(requestBuffer, 0, received)
                .Contains("\r\n\r\n", StringComparison.Ordinal))
            {
                break;
            }
        }

        const string response =
            "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\ntoken.thumbprint";
        await stream
            .WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken)
            .ConfigureAwait(false);
    }

    private static PinnedHttp01Transport CreateLoopbackTransport(
        TcpListener listener) =>
        new(
            async (_, _, cancellationToken) =>
            {
                var socket = new Socket(
                    AddressFamily.InterNetwork,
                    SocketType.Stream,
                    ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(
                            (IPEndPoint)listener.LocalEndpoint,
                            cancellationToken)
                        .ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            });

    private static async Task ServeRawHttpResponseAsync(
        TcpListener listener,
        string response,
        TaskCompletionSource? responseSent = null,
        Task? holdOpen = null)
    {
        using var socket = await listener
            .AcceptSocketAsync()
            .ConfigureAwait(false);
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        var requestBuffer = new byte[4096];
        var received = 0;
        while (received < requestBuffer.Length)
        {
            var read = await stream
                .ReadAsync(requestBuffer.AsMemory(received))
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("The test HTTP request ended early.");
            }

            received += read;
            if (Encoding.ASCII
                .GetString(requestBuffer, 0, received)
                .Contains("\r\n\r\n", StringComparison.Ordinal))
            {
                break;
            }
        }

        await stream
            .WriteAsync(Encoding.ASCII.GetBytes(response))
            .ConfigureAwait(false);
        responseSent?.TrySetResult();
        if (holdOpen is not null)
        {
            await holdOpen.ConfigureAwait(false);
        }
    }

    private sealed class ScriptedPinnedTransport(
        params PinnedHttp01Response[] responses) : IPinnedHttp01Transport
    {
        private readonly Queue<PinnedHttp01Response> responses = new(responses);

        public List<PinnedRequest> Requests { get; } = [];

        public Task<PinnedHttp01Response> SendAsync(
            Uri requestUri,
            IReadOnlyList<IPAddress> addresses,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(new PinnedRequest(requestUri, addresses.ToArray()));
            return Task.FromResult(responses.Dequeue());
        }
    }

    private sealed record PinnedRequest(
        Uri RequestUri,
        IReadOnlyList<IPAddress> Addresses);
}
