namespace CertBaton.Contracts;

public sealed record IpcRequest(
    int ProtocolVersion,
    Guid RequestId,
    string Method,
    DateTimeOffset SentAtUtc,
    DateTimeOffset DeadlineUtc)
{
    public static IpcRequest CreateHealth(
        TimeProvider timeProvider,
        TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        var requestTimeout = timeout ?? IpcProtocol.DefaultRequestTimeout;
        if (requestTimeout <= TimeSpan.Zero ||
            requestTimeout > IpcProtocol.MaximumRequestHorizon)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timeout),
                $"The request timeout must be greater than zero and no more than {IpcProtocol.MaximumRequestHorizon.TotalSeconds:0} seconds.");
        }

        var sentAtUtc = timeProvider.GetUtcNow();
        return new IpcRequest(
            IpcProtocol.CurrentVersion,
            Guid.NewGuid(),
            IpcProtocol.HealthMethod,
            sentAtUtc,
            sentAtUtc.Add(requestTimeout));
    }
}
