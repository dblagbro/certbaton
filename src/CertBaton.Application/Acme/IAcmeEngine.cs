namespace CertBaton.Application.Acme;

public interface IAcmeEngine
{
    Task<AcmeAccountResult> EnsureAccountAsync(
        AcmeAccountRequest request,
        CancellationToken cancellationToken = default);

    Task<AcmeOrder> CreateOrderAsync(
        AcmeAccount account,
        AcmeOrderRequest request,
        CancellationToken cancellationToken = default);

    Task<AcmeOrder> GetOrderAsync(
        AcmeAccount account,
        Uri orderUri,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AcmeHttp01Challenge>> GetHttp01ChallengesAsync(
        AcmeAccount account,
        Uri orderUri,
        CancellationToken cancellationToken = default);

    Task<AcmeChallenge> AnswerHttp01ChallengeAsync(
        AcmeAccount account,
        AcmeHttp01Challenge challenge,
        CancellationToken cancellationToken = default);

    Task<AcmeChallengePollResult> PollHttp01ChallengeAsync(
        AcmeAccount account,
        AcmeHttp01Challenge challenge,
        AcmePollingPolicy? policy = null,
        CancellationToken cancellationToken = default);

    Task<AcmeOrder> FinalizeOrderAsync(
        AcmeAccount account,
        Uri orderUri,
        ReadOnlyMemory<byte> certificateSigningRequestDer,
        CancellationToken cancellationToken = default);

    Task<AcmeOrderPollResult> PollOrderAsync(
        AcmeAccount account,
        Uri orderUri,
        AcmePollingPolicy? policy = null,
        CancellationToken cancellationToken = default);

    Task<AcmeCertificateChain> DownloadCertificateAsync(
        AcmeAccount account,
        Uri orderUri,
        string? preferredChain = null,
        CancellationToken cancellationToken = default);
}
