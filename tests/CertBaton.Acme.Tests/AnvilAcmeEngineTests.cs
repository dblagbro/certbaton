using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertBaton.Acme.Anvil;
using CertBaton.Application.Acme;
using Certify.ACME.Anvil;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Acme.Resource;
using AnvilDirectory = Certify.ACME.Anvil.Acme.Resource.Directory;

namespace CertBaton.Acme.Tests;

[TestClass]
public sealed class AnvilAcmeEngineTests
{
    private static readonly Uri directoryUri = new("https://acme.test/directory");
    private static readonly Uri nonceUri = new("https://acme.test/new-nonce");
    private static readonly Uri newAccountUri = new("https://acme.test/new-account");
    private static readonly Uri accountUri = new("https://acme.test/account/7");
    private static readonly Uri newOrderUri = new("https://acme.test/new-order");
    private static readonly Uri orderUri = new("https://acme.test/order/11");
    private static readonly Uri authorizationUri = new("https://acme.test/authz/13");
    private static readonly Uri challengeUri = new("https://acme.test/challenge/17");
    private static readonly Uri finalizeUri = new("https://acme.test/order/11/finalize");
    private static readonly Uri certificateUri = new("https://acme.test/certificate/19");
    private static readonly string[] expectedDnsIdentifiers = ["www.example.test"];

    [TestMethod]
    public async Task AdapterCompletesAccountOrderHttp01AndCertificateLifecycle()
    {
        var http = new ScriptedAcmeHttpClient();
        var directory = CreateDirectory();
        var accountResource = new Account { Status = AccountStatus.Valid };
        var pendingOrder = CreateOrder(OrderStatus.Pending);
        var readyOrder = CreateOrder(OrderStatus.Ready);
        var processingOrder = CreateOrder(OrderStatus.Processing);
        var validOrder = CreateOrder(OrderStatus.Valid);
        var pendingAuthorization = CreateAuthorization(ChallengeStatus.Pending);
        var certificatePem = CreateCertificatePem();

        http.EnqueueGet(directoryUri, directory);
        http.EnqueuePost(newAccountUri, accountResource, accountUri);
        http.EnqueuePost(accountUri, accountResource);
        http.EnqueuePost(accountUri, accountResource);
        http.EnqueueGet(directoryUri, directory);
        http.EnqueuePost(newOrderUri, pendingOrder, orderUri);
        http.EnqueuePost(orderUri, pendingOrder);
        http.EnqueuePost(orderUri, pendingOrder);
        http.EnqueuePost(authorizationUri, pendingAuthorization);
        http.EnqueuePost(authorizationUri, pendingAuthorization);
        http.EnqueuePost(
            challengeUri,
            CreateChallenge(ChallengeStatus.Processing));
        http.EnqueuePost(authorizationUri, pendingAuthorization);
        http.EnqueuePost(challengeUri, CreateChallenge(ChallengeStatus.Pending));
        http.EnqueuePost(
            challengeUri,
            CreateChallenge(
                ChallengeStatus.Valid,
                new DateTimeOffset(2026, 7, 31, 12, 0, 0, TimeSpan.Zero)));
        http.EnqueuePost(orderUri, readyOrder);
        http.EnqueuePost(finalizeUri, processingOrder);
        http.EnqueuePost(orderUri, processingOrder);
        http.EnqueuePost(orderUri, validOrder);
        http.EnqueuePost(orderUri, validOrder);
        http.EnqueuePost(orderUri, validOrder);
        http.EnqueuePost(certificateUri, certificatePem);

        var engine = new AnvilAcmeEngine(_ => http, TimeProvider.System);
        var created = await engine.EnsureAccountAsync(
            new AcmeAccountRequest(
                directoryUri,
                ["mailto:operator@example.test"],
                termsOfServiceAgreed: true));

        Assert.IsTrue(created.Created);
        using var accountLifetime = created.Account;
        Assert.AreEqual(AcmeResourceStatus.Valid, created.Status);
        Assert.AreEqual(accountUri, created.Account.AccountUri);
        Assert.IsTrue(created.Account.ExportAccountKeyPem().Length > 0);

        var reused = await engine.EnsureAccountAsync(
            new AcmeAccountRequest(
                directoryUri,
                [],
                termsOfServiceAgreed: true,
                created.Account));
        Assert.IsFalse(reused.Created);
        Assert.AreSame(created.Account, reused.Account);

        var order = await engine.CreateOrderAsync(
            created.Account,
            new AcmeOrderRequest(["www.example.test"], profile: "shortlived"));
        Assert.AreEqual(orderUri, order.OrderUri);
        Assert.AreEqual(AcmeResourceStatus.Pending, order.Status);
        CollectionAssert.AreEqual(
            expectedDnsIdentifiers,
            order.DnsIdentifiers.ToArray());

        var challenges = await engine.GetHttp01ChallengesAsync(
            created.Account,
            order.OrderUri);
        Assert.HasCount(1, challenges);
        var challenge = challenges[0];
        Assert.AreEqual("www.example.test", challenge.Identifier);
        Assert.AreEqual("challenge-token", challenge.Token);
        StringAssert.StartsWith(challenge.KeyAuthorization, "challenge-token.");

        var answered = await engine.AnswerHttp01ChallengeAsync(
            created.Account,
            challenge);
        Assert.AreEqual(AcmeResourceStatus.Processing, answered.Status);

        var challengePoll = await engine.PollHttp01ChallengeAsync(
            created.Account,
            challenge,
            new AcmePollingPolicy(3, TimeSpan.Zero));
        Assert.IsFalse(challengePoll.TimedOut);
        Assert.AreEqual(2, challengePoll.Attempts);
        Assert.AreEqual(AcmeResourceStatus.Valid, challengePoll.Challenge.Status);

        var finalized = await engine.FinalizeOrderAsync(
            created.Account,
            order.OrderUri,
            new byte[] { 0x30, 0x00 });
        Assert.AreEqual(AcmeResourceStatus.Processing, finalized.Status);

        var orderPoll = await engine.PollOrderAsync(
            created.Account,
            order.OrderUri,
            new AcmePollingPolicy(3, TimeSpan.Zero));
        Assert.IsFalse(orderPoll.TimedOut);
        Assert.AreEqual(2, orderPoll.Attempts);
        Assert.AreEqual(AcmeResourceStatus.Valid, orderPoll.Order.Status);

        var certificate = await engine.DownloadCertificateAsync(
            created.Account,
            order.OrderUri);
        Assert.AreEqual(certificatePem.Trim(), certificate.LeafCertificatePem.Trim());
        StringAssert.Contains(certificate.FullChainPem, "BEGIN CERTIFICATE");
        Assert.IsEmpty(certificate.IssuerCertificatesPem);
        http.AssertComplete();
    }

    [TestMethod]
    public async Task ChallengePollingStopsAtConfiguredBound()
    {
        var http = new ScriptedAcmeHttpClient();
        var authorization = CreateAuthorization(ChallengeStatus.Pending);
        http.EnqueuePost(authorizationUri, authorization);
        http.EnqueuePost(challengeUri, CreateChallenge(ChallengeStatus.Pending));
        http.EnqueuePost(challengeUri, CreateChallenge(ChallengeStatus.Pending));

        var engine = new AnvilAcmeEngine(_ => http, TimeProvider.System);
        using var storedAccount = CreateStoredAccount();
        var result = await engine.PollHttp01ChallengeAsync(
            storedAccount,
            CreateContractChallenge(),
            new AcmePollingPolicy(2, TimeSpan.Zero));

        Assert.IsTrue(result.TimedOut);
        Assert.AreEqual(2, result.Attempts);
        Assert.AreEqual(AcmeResourceStatus.Pending, result.Challenge.Status);
        http.AssertComplete();
    }

    [TestMethod]
    public async Task ServerProblemIsMappedWithoutLeakingAnvilTypeAcrossContract()
    {
        var http = new ScriptedAcmeHttpClient();
        var problem = new AcmeError
        {
            Type = "urn:ietf:params:acme:error:unauthorized",
            Detail = "Account access was denied.",
            Status = System.Net.HttpStatusCode.Unauthorized,
        };
        http.EnqueuePost<Account>(accountUri, null!, error: problem);

        var engine = new AnvilAcmeEngine(_ => http, TimeProvider.System);
        using var storedAccount = CreateStoredAccount();
        var exception = await Assert.ThrowsExactlyAsync<AcmeEngineException>(
            () => engine.EnsureAccountAsync(
                new AcmeAccountRequest(
                    directoryUri,
                    [],
                    termsOfServiceAgreed: true,
                    storedAccount)));

        Assert.AreEqual("reuse-account", exception.Operation);
        Assert.AreEqual(problem.Type, exception.Problem?.Type);
        Assert.AreEqual(401, exception.Problem?.HttpStatus);
        Assert.IsNull(exception.InnerException);
        Assert.AreEqual(
            typeof(CertBaton.Application.Acme.IAcmeEngine).Assembly,
            typeof(AcmeEngineException).Assembly);
        Assert.IsFalse(
            typeof(CertBaton.Application.Acme.IAcmeEngine).Assembly
                .GetReferencedAssemblies()
                .Any(static assembly => assembly.Name?.Contains("Anvil", StringComparison.Ordinal) == true));
        http.AssertComplete();
    }

    [TestMethod]
    public async Task BadNonceRetriesAreBounded()
    {
        var http = new ScriptedAcmeHttpClient();
        var badNonce = new AcmeError
        {
            Type = "urn:ietf:params:acme:error:badNonce",
            Detail = "The nonce was rejected.",
            Status = System.Net.HttpStatusCode.BadRequest,
        };
        for (var attempt = 0; attempt < 3; attempt++)
        {
            http.EnqueuePost<Account>(accountUri, null!, error: badNonce);
        }

        var engine = new AnvilAcmeEngine(_ => http, TimeProvider.System);
        using var storedAccount = CreateStoredAccount();
        var exception = await Assert.ThrowsExactlyAsync<AcmeEngineException>(
            () => engine.EnsureAccountAsync(
                new AcmeAccountRequest(
                    directoryUri,
                    [],
                    termsOfServiceAgreed: true,
                    storedAccount)));

        Assert.AreEqual("reuse-account", exception.Operation);
        Assert.AreEqual(badNonce.Type, exception.Problem?.Type);
        http.AssertComplete();
    }

    [TestMethod]
    public void AccountKeyIsDefensivelyCopiedAndRedacted()
    {
        var source = Encoding.UTF8.GetBytes("private-account-key");
        using var account = new CertBaton.Application.Acme.AcmeAccount(
            directoryUri,
            accountUri,
            source);
        source[0] = 0;

        var exported = account.ExportAccountKeyPem();
        Assert.AreEqual((byte)'p', exported[0]);
        exported[0] = 0;
        Assert.AreEqual((byte)'p', account.ExportAccountKeyPem()[0]);
        StringAssert.Contains(account.ToString(), "key redacted");
        Assert.DoesNotContain("private-account-key", account.ToString());

        account.Dispose();
        Assert.ThrowsExactly<ObjectDisposedException>(account.ExportAccountKeyPem);
    }

    private static AnvilDirectory CreateDirectory() =>
        new(
            nonceUri,
            newAccountUri,
            newOrderUri,
            new Uri("https://acme.test/revoke"),
            new Uri("https://acme.test/key-change"),
            renewalInfo: null,
            meta: null);

    private static Order CreateOrder(OrderStatus status) =>
        new()
        {
            Status = status,
            Identifiers =
            [
                new Identifier
                {
                    Type = IdentifierType.Dns,
                    Value = "www.example.test",
                },
            ],
            Authorizations = [authorizationUri],
            Finalize = finalizeUri,
            Certificate = status == OrderStatus.Valid ? certificateUri : null,
        };

    private static Authorization CreateAuthorization(ChallengeStatus challengeStatus) =>
        new()
        {
            Identifier = new Identifier
            {
                Type = IdentifierType.Dns,
                Value = "www.example.test",
            },
            Status = AuthorizationStatus.Pending,
            Challenges = [CreateChallenge(challengeStatus)],
        };

    private static Challenge CreateChallenge(
        ChallengeStatus status,
        DateTimeOffset? validated = null) =>
        new()
        {
            Type = ChallengeTypes.Http01,
            Url = challengeUri,
            Status = status,
            Token = "challenge-token",
            Validated = validated,
        };

    private static AcmeHttp01Challenge CreateContractChallenge() =>
        new(
            "www.example.test",
            IsWildcard: false,
            authorizationUri,
            challengeUri,
            "challenge-token",
            "challenge-token.thumbprint",
            AcmeResourceStatus.Pending,
            Validated: null,
            Problem: null);

    private static CertBaton.Application.Acme.AcmeAccount CreateStoredAccount()
    {
        var key = KeyFactory.NewKey(KeyAlgorithm.ES256);
        return new CertBaton.Application.Acme.AcmeAccount(
            directoryUri,
            accountUri,
            Encoding.UTF8.GetBytes(key.ToPem()));
    }

    private static string CreateCertificatePem()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=www.example.test",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        return certificate.ExportCertificatePem();
    }
}
