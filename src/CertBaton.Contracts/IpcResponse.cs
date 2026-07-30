namespace CertBaton.Contracts;

public sealed record IpcResponse(
    int ProtocolVersion,
    Guid RequestId,
    bool Success,
    IpcResultEnvelope? Result,
    IpcError? Error)
{
    public static IpcResponse Succeeded(Guid requestId, HealthSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(result, null),
            null);
    }

    public static IpcResponse Succeeded(
        Guid requestId,
        SimulationRunSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(null, result),
            null);
    }

    public static IpcResponse Failed(Guid requestId, string code, string message) =>
        new(
            IpcProtocol.CurrentVersion,
            requestId,
            false,
            null,
            new IpcError(code, message));

    public bool TryValidateForMethod(string method, out string? error)
    {
        if (!Success)
        {
            if (Result is not null || Error is null)
            {
                error = "A failed response must contain an error and no result.";
                return false;
            }

            error = null;
            return true;
        }

        if (Error is not null || Result is null)
        {
            error = "A successful response must contain a result and no error.";
            return false;
        }

        var payloadCount =
            (Result.Health is null ? 0 : 1) +
            (Result.SimulationRun is null ? 0 : 1);
        if (payloadCount != 1)
        {
            error =
                "A successful response result must contain exactly one typed payload.";
            return false;
        }

        switch (method)
        {
            case IpcProtocol.HealthMethod:
                if (Result.Health is null)
                {
                    error = "A health request must return a health result.";
                    return false;
                }

                break;

            case IpcProtocol.SimulationStartMethod:
            case IpcProtocol.SimulationLatestMethod:
                if (Result.SimulationRun is null)
                {
                    error =
                        "A simulation request must return a simulation run result.";
                    return false;
                }

                if (!Result.SimulationRun.TryValidate(out error))
                {
                    return false;
                }

                break;

            default:
                error = "An unregistered method cannot return a successful result.";
                return false;
        }

        error = null;
        return true;
    }
}

public sealed record IpcError(string Code, string Message);

public sealed record IpcResultEnvelope(
    HealthSnapshot? Health,
    SimulationRunSnapshot? SimulationRun);

public sealed record HealthSnapshot(
    string Status,
    string ServiceVersion,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset RespondedAtUtc);
