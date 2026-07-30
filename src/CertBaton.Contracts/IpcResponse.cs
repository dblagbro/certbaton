namespace CertBaton.Contracts;

public sealed record IpcResponse(
    int ProtocolVersion,
    Guid RequestId,
    bool Success,
    HealthSnapshot? Result,
    IpcError? Error)
{
    public static IpcResponse Succeeded(Guid requestId, HealthSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            result,
            null);
    }

    public static IpcResponse Failed(Guid requestId, string code, string message) =>
        new(
            IpcProtocol.CurrentVersion,
            requestId,
            false,
            null,
            new IpcError(code, message));
}

public sealed record IpcError(string Code, string Message);

public sealed record HealthSnapshot(
    string Status,
    string ServiceVersion,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset RespondedAtUtc);
