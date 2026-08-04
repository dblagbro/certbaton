using System.Security.Cryptography;
using System.Text;
using CertBaton.Application.Acme;
using Certify.ACME.Anvil;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Acme.Resource;
using AnvilChallenge = Certify.ACME.Anvil.Acme.Resource.Challenge;
using AnvilChallengeStatus = Certify.ACME.Anvil.Acme.Resource.ChallengeStatus;
using AnvilOrder = Certify.ACME.Anvil.Acme.Resource.Order;
using AnvilOrderStatus = Certify.ACME.Anvil.Acme.Resource.OrderStatus;
using CertBatonAccount = CertBaton.Application.Acme.AcmeAccount;

namespace CertBaton.Acme.Anvil;

public sealed class AnvilAcmeEngine : IAcmeEngine
{
    private readonly Func<Uri, IAcmeHttpClient?> httpClientFactory;
    private readonly TimeProvider timeProvider;

    public AnvilAcmeEngine(TimeProvider? timeProvider = null)
        : this(static _ => null, timeProvider ?? TimeProvider.System)
    {
    }

    internal AnvilAcmeEngine(
        Func<Uri, IAcmeHttpClient?> httpClientFactory,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(httpClientFactory);
        ArgumentNullException.ThrowIfNull(timeProvider);
        this.httpClientFactory = httpClientFactory;
        this.timeProvider = timeProvider;
    }

    public async Task<AcmeAccountResult> EnsureAccountAsync(
        AcmeAccountRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        if (request.ExistingAccount is { } existingAccount)
        {
            var existingContext = CreateContext(existingAccount);
            var existing = await ExecuteAsync(
                    "reuse-account",
                    () => existingContext.Account(existingAccount.AccountUri),
                    cancellationToken)
                .ConfigureAwait(false);
            var resource = await ExecuteAsync(
                    "reuse-account",
                    existing.Resource,
                    cancellationToken)
                .ConfigureAwait(false);

            return new AcmeAccountResult(
                existingAccount,
                MapStatus(resource.Status),
                Created: false);
        }

        var context = CreateContext(request.DirectoryUri);
        var accountContext = await ExecuteAsync(
                "create-account",
                () => context.NewAccount(
                    request.ContactUris.ToArray(),
                    request.TermsOfServiceAgreed),
                cancellationToken)
            .ConfigureAwait(false);
        var accountResource = await ExecuteAsync(
                "create-account",
                accountContext.Resource,
                cancellationToken)
            .ConfigureAwait(false);

        var keyPem = Encoding.UTF8.GetBytes(context.AccountKey.ToPem());
        CertBatonAccount account;
        try
        {
            account = new CertBatonAccount(
                request.DirectoryUri,
                accountContext.Location,
                keyPem);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyPem);
        }

        return new AcmeAccountResult(
            account,
            MapStatus(accountResource.Status),
            Created: true);
    }

    public async Task<AcmeOrder> CreateOrderAsync(
        CertBatonAccount account,
        AcmeOrderRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(request);

        var context = CreateContext(account);
        var orderContext = await ExecuteAsync(
                "create-order",
                () => context.NewOrder(
                    request.DnsIdentifiers.ToArray(),
                    request.NotBefore,
                    request.NotAfter,
                    request.ReplacesCertificateId,
                    request.Profile),
                cancellationToken)
            .ConfigureAwait(false);
        var resource = await ExecuteAsync(
                "create-order",
                orderContext.Resource,
                cancellationToken)
            .ConfigureAwait(false);

        return MapOrder(orderContext.Location, resource);
    }

    public async Task<AcmeOrder> GetOrderAsync(
        CertBatonAccount account,
        Uri orderUri,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        ValidateResourceUri(orderUri, nameof(orderUri));

        var order = CreateContext(account).Order(orderUri);
        var resource = await ExecuteAsync(
                "get-order",
                order.Resource,
                cancellationToken)
            .ConfigureAwait(false);

        return MapOrder(orderUri, resource);
    }

    public async Task<IReadOnlyList<AcmeHttp01Challenge>> GetHttp01ChallengesAsync(
        CertBatonAccount account,
        Uri orderUri,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        ValidateResourceUri(orderUri, nameof(orderUri));

        var context = CreateContext(account);
        var order = context.Order(orderUri);
        var orderResource = await ExecuteAsync(
                "get-http-01-challenges",
                order.Resource,
                cancellationToken)
            .ConfigureAwait(false);
        var challenges = new List<AcmeHttp01Challenge>();

        foreach (var authorizationUri in orderResource.Authorizations ?? [])
        {
            ValidateResourceUri(authorizationUri, "authorizationUri");
            var authorization = context.Authorization(authorizationUri);
            var resource = await ExecuteAsync(
                    "get-http-01-challenges",
                    authorization.Resource,
                    cancellationToken)
                .ConfigureAwait(false);

            var challenge = resource.Challenges?.FirstOrDefault(
                static candidate => string.Equals(
                    candidate.Type,
                    ChallengeTypes.Http01,
                    StringComparison.Ordinal));
            if (challenge is null)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(resource.Identifier?.Value) ||
                challenge.Url is null ||
                string.IsNullOrWhiteSpace(challenge.Token))
            {
                throw new AcmeEngineException(
                    "get-http-01-challenges",
                    "The ACME server returned an incomplete HTTP-01 challenge resource.");
            }

            ValidateResourceUri(challenge.Url, "challengeUri");

            challenges.Add(new AcmeHttp01Challenge(
                resource.Identifier.Value,
                resource.Wildcard.GetValueOrDefault(),
                authorizationUri,
                challenge.Url,
                challenge.Token,
                context.AccountKey.KeyAuthorization(challenge.Token),
                MapStatus(challenge.Status),
                challenge.Validated,
                MapProblem(challenge.Error)));
        }

        return challenges.AsReadOnly();
    }

    public async Task<AcmeChallenge> AnswerHttp01ChallengeAsync(
        CertBatonAccount account,
        AcmeHttp01Challenge challenge,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(challenge);

        var challengeContext = await FindChallengeAsync(
                CreateContext(account),
                challenge,
                "answer-http-01-challenge",
                cancellationToken)
            .ConfigureAwait(false);
        var resource = await ExecuteAsync(
                "answer-http-01-challenge",
                () => challengeContext.Validate(),
                cancellationToken)
            .ConfigureAwait(false);

        return MapChallenge(challenge.ChallengeUri, resource);
    }

    public async Task<AcmeChallengePollResult> PollHttp01ChallengeAsync(
        CertBatonAccount account,
        AcmeHttp01Challenge challenge,
        AcmePollingPolicy? policy = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(challenge);
        policy ??= AcmePollingPolicy.Default;

        var challengeContext = await FindChallengeAsync(
                CreateContext(account),
                challenge,
                "poll-http-01-challenge",
                cancellationToken)
            .ConfigureAwait(false);

        AcmeChallenge? last = null;
        for (var attempt = 1; attempt <= policy.MaxAttempts; attempt++)
        {
            var resource = await ExecuteAsync(
                    "poll-http-01-challenge",
                    challengeContext.Resource,
                    cancellationToken)
                .ConfigureAwait(false);
            last = MapChallenge(challenge.ChallengeUri, resource);
            if (IsChallengeTerminal(last.Status))
            {
                return new AcmeChallengePollResult(last, attempt, TimedOut: false);
            }

            if (attempt < policy.MaxAttempts)
            {
                await DelayAsync(policy.Interval, cancellationToken).ConfigureAwait(false);
            }
        }

        return new AcmeChallengePollResult(
            last!,
            policy.MaxAttempts,
            TimedOut: true);
    }

    public async Task<AcmeOrder> FinalizeOrderAsync(
        CertBatonAccount account,
        Uri orderUri,
        ReadOnlyMemory<byte> certificateSigningRequestDer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        ValidateResourceUri(orderUri, nameof(orderUri));
        if (certificateSigningRequestDer.IsEmpty)
        {
            throw new ArgumentException(
                "The DER-encoded certificate signing request cannot be empty.",
                nameof(certificateSigningRequestDer));
        }

        var order = CreateContext(account).Order(orderUri);
        var resource = await ExecuteAsync(
                "finalize-order",
                () => order.Finalize(certificateSigningRequestDer.ToArray()),
                cancellationToken)
            .ConfigureAwait(false);

        return MapOrder(orderUri, resource);
    }

    public async Task<AcmeOrderPollResult> PollOrderAsync(
        CertBatonAccount account,
        Uri orderUri,
        AcmePollingPolicy? policy = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        ValidateResourceUri(orderUri, nameof(orderUri));
        policy ??= AcmePollingPolicy.Default;

        var orderContext = CreateContext(account).Order(orderUri);
        AcmeOrder? last = null;
        for (var attempt = 1; attempt <= policy.MaxAttempts; attempt++)
        {
            var resource = await ExecuteAsync(
                    "poll-order",
                    orderContext.Resource,
                    cancellationToken)
                .ConfigureAwait(false);
            last = MapOrder(orderUri, resource);
            if (IsOrderTerminal(last.Status))
            {
                return new AcmeOrderPollResult(last, attempt, TimedOut: false);
            }

            if (attempt < policy.MaxAttempts)
            {
                await DelayAsync(policy.Interval, cancellationToken).ConfigureAwait(false);
            }
        }

        return new AcmeOrderPollResult(
            last!,
            policy.MaxAttempts,
            TimedOut: true);
    }

    public async Task<AcmeCertificateChain> DownloadCertificateAsync(
        CertBatonAccount account,
        Uri orderUri,
        string? preferredChain = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        ValidateResourceUri(orderUri, nameof(orderUri));

        var order = CreateContext(account).Order(orderUri);
        var current = await ExecuteAsync(
                "download-certificate",
                order.Resource,
                cancellationToken)
            .ConfigureAwait(false);
        if (current.Status != AnvilOrderStatus.Valid)
        {
            throw new AcmeEngineException(
                "download-certificate",
                $"The ACME order is '{current.Status?.ToString() ?? "unknown"}', not valid.",
                MapProblem(current.Error));
        }

        ValidateResourceUri(current.Certificate, "certificateUri");

        var chain = await ExecuteAsync(
                "download-certificate",
                () => order.Download(
                    string.IsNullOrWhiteSpace(preferredChain)
                        ? null
                        : preferredChain.Trim()),
                cancellationToken)
            .ConfigureAwait(false);
        var issuerCertificates = chain.Issuers
            .Select(static issuer => issuer.ToPem())
            .ToArray();

        return new AcmeCertificateChain(
            chain.Certificate.ToPem(),
            Array.AsReadOnly(issuerCertificates),
            chain.ToPem());
    }

    private AcmeContext CreateContext(Uri directoryUri) =>
        new(
            directoryUri,
            http: httpClientFactory(directoryUri),
            badNonceRetryCount: 2);

    private AcmeContext CreateContext(CertBatonAccount account)
    {
        var keyBytes = account.ExportAccountKeyPem();
        IKey key;
        try
        {
            var keyPem = Encoding.UTF8.GetString(keyBytes);
            key = KeyFactory.FromPem(keyPem);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        return new AcmeContext(
            account.DirectoryUri,
            key,
            httpClientFactory(account.DirectoryUri),
            badNonceRetryCount: 2,
            account.AccountUri);
    }

    private static async Task<IChallengeContext> FindChallengeAsync(
        AcmeContext context,
        AcmeHttp01Challenge challenge,
        string operation,
        CancellationToken cancellationToken)
    {
        ValidateResourceUri(challenge.AuthorizationUri, nameof(challenge.AuthorizationUri));
        ValidateResourceUri(challenge.ChallengeUri, nameof(challenge.ChallengeUri));
        var authorization = context.Authorization(challenge.AuthorizationUri);
        var candidates = await ExecuteAsync(
                operation,
                authorization.Challenges,
                cancellationToken)
            .ConfigureAwait(false);
        var match = candidates.FirstOrDefault(candidate =>
            string.Equals(candidate.Type, ChallengeTypes.Http01, StringComparison.Ordinal) &&
            candidate.Location == challenge.ChallengeUri &&
            string.Equals(candidate.Token, challenge.Token, StringComparison.Ordinal));

        return match ?? throw new AcmeEngineException(
            operation,
            "The HTTP-01 challenge is no longer present on the authorization.");
    }

    private async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        if (delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, timeProvider, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    private static async Task<T> ExecuteAsync<T>(
        string operation,
        Func<Task<T>> action,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await action().WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (AcmeRequestException exception)
        {
            throw new AcmeEngineException(
                operation,
                $"The ACME server rejected the '{operation}' operation.",
                MapProblem(exception.Error));
        }
        catch (AcmeException)
        {
            throw new AcmeEngineException(
                operation,
                $"The ACME client could not complete the '{operation}' operation.");
        }
    }

    private static AcmeOrder MapOrder(Uri orderUri, AnvilOrder order)
    {
        ValidateResourceUri(orderUri, nameof(orderUri));
        return new AcmeOrder(
            orderUri,
            Array.AsReadOnly(
                (order.Identifiers ?? [])
                .Where(static identifier => identifier.Type == IdentifierType.Dns)
                .Select(static identifier => identifier.Value)
                .ToArray()),
            MapStatus(order.Status),
            order.Expires,
            MapProblem(order.Error));
    }

    private static AcmeChallenge MapChallenge(Uri challengeUri, AnvilChallenge challenge) =>
        new(
            challengeUri,
            MapStatus(challenge.Status),
            challenge.Validated,
            MapProblem(challenge.Error));

    private static AcmeResourceStatus MapStatus(AccountStatus? status) => status switch
    {
        AccountStatus.Valid => AcmeResourceStatus.Valid,
        AccountStatus.Deactivated => AcmeResourceStatus.Deactivated,
        AccountStatus.Revoked => AcmeResourceStatus.Revoked,
        _ => AcmeResourceStatus.Unknown,
    };

    private static AcmeResourceStatus MapStatus(AnvilOrderStatus? status) => status switch
    {
        AnvilOrderStatus.Pending => AcmeResourceStatus.Pending,
        AnvilOrderStatus.Ready => AcmeResourceStatus.Ready,
        AnvilOrderStatus.Processing => AcmeResourceStatus.Processing,
        AnvilOrderStatus.Valid => AcmeResourceStatus.Valid,
        AnvilOrderStatus.Invalid => AcmeResourceStatus.Invalid,
        _ => AcmeResourceStatus.Unknown,
    };

    private static AcmeResourceStatus MapStatus(AnvilChallengeStatus? status) => status switch
    {
        AnvilChallengeStatus.Pending => AcmeResourceStatus.Pending,
        AnvilChallengeStatus.Processing => AcmeResourceStatus.Processing,
        AnvilChallengeStatus.Valid => AcmeResourceStatus.Valid,
        AnvilChallengeStatus.Invalid => AcmeResourceStatus.Invalid,
        _ => AcmeResourceStatus.Unknown,
    };

    private static AcmeProblem? MapProblem(object? error) => error switch
    {
        null => null,
        AcmeError problem => MapProblem(problem),
        _ => new AcmeProblem(null, error.ToString(), null, null),
    };

    private static AcmeProblem? MapProblem(AcmeError? error) => error is null
        ? null
        : new AcmeProblem(
            error.Type,
            error.Detail,
            error.Status == 0 ? null : (int)error.Status,
            error.Identifier?.Value,
            error.Subproblems?.Select(static problem => MapProblem(problem)!));

    private static bool IsChallengeTerminal(AcmeResourceStatus status) =>
        status is AcmeResourceStatus.Valid or AcmeResourceStatus.Invalid;

    private static bool IsOrderTerminal(AcmeResourceStatus status) =>
        status is AcmeResourceStatus.Ready or
            AcmeResourceStatus.Valid or
            AcmeResourceStatus.Invalid;

    private static void ValidateResourceUri(Uri uri, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(uri, parameterName);
        if (!uri.IsAbsoluteUri ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The ACME resource URI must be an absolute HTTPS URI.",
                parameterName);
        }
    }
}
