namespace CertBaton.Contracts;

public sealed record IpcRequest(
    int ProtocolVersion,
    Guid RequestId,
    string Method,
    DateTimeOffset SentAtUtc,
    DateTimeOffset DeadlineUtc,
    SimulationStartPayload? Payload = null)
{
    public static IpcRequest CreateHealth(
        TimeProvider timeProvider,
        TimeSpan? timeout = null) =>
        Create(
            timeProvider,
            IpcProtocol.HealthMethod,
            null,
            timeout);

    public static IpcRequest CreateSimulationLatest(
        TimeProvider timeProvider,
        TimeSpan? timeout = null) =>
        Create(
            timeProvider,
            IpcProtocol.SimulationLatestMethod,
            null,
            timeout);

    public static IpcRequest CreateSimulationStart(
        TimeProvider timeProvider,
        Guid idempotencyKey,
        string? failureStage = null,
        TimeSpan? timeout = null)
    {
        if (idempotencyKey == Guid.Empty)
        {
            throw new ArgumentException(
                "A non-empty simulation idempotency key is required.",
                nameof(idempotencyKey));
        }

        if (failureStage is not null &&
            !SimulationContractValues.IsStage(failureStage))
        {
            throw new ArgumentException(
                $"The simulation failure stage must be one of: {string.Join(", ", SimulationContractValues.Stages)}.",
                nameof(failureStage));
        }

        var payload = new SimulationStartPayload(idempotencyKey, failureStage);
        return Create(
            timeProvider,
            IpcProtocol.SimulationStartMethod,
            payload,
            timeout);
    }

    public bool TryValidateMethodPayload(out string? error)
    {
        switch (Method)
        {
            case IpcProtocol.HealthMethod:
            case IpcProtocol.SimulationLatestMethod:
                if (Payload is not null)
                {
                    error = $"Method '{Method}' does not accept a payload.";
                    return false;
                }

                break;

            case IpcProtocol.SimulationStartMethod:
                if (Payload is null)
                {
                    error = $"Method '{Method}' requires a payload.";
                    return false;
                }

                if (!Payload.TryValidate(out error))
                {
                    return false;
                }

                break;

            default:
                if (Payload is not null)
                {
                    error = "An unregistered method cannot carry a typed payload.";
                    return false;
                }

                break;
        }

        error = null;
        return true;
    }

    private static IpcRequest Create(
        TimeProvider timeProvider,
        string method,
        SimulationStartPayload? payload,
        TimeSpan? timeout)
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
            method,
            sentAtUtc,
            sentAtUtc.Add(requestTimeout),
            payload);
    }
}

public sealed record SimulationStartPayload(
    Guid IdempotencyKey,
    string? FailureStage = null)
{
    public bool TryValidate(out string? error)
    {
        if (IdempotencyKey == Guid.Empty)
        {
            error = "A non-empty simulation idempotency key is required.";
            return false;
        }

        if (FailureStage is not null &&
            !SimulationContractValues.IsStage(FailureStage))
        {
            error =
                $"The simulation failure stage must be one of: {string.Join(", ", SimulationContractValues.Stages)}.";
            return false;
        }

        error = null;
        return true;
    }
}
