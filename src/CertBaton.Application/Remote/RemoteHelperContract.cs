namespace CertBaton.Application.Remote;

public enum RemoteHelperVerbV1
{
    Prepare = 0,
    Validate = 1,
    Activate = 2,
    Verify = 3,
    Rollback = 4,
    Commit = 5,
    Abort = 6,
    Status = 7,
}

public readonly record struct RemoteTransactionId
{
    public RemoteTransactionId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Remote transaction ID cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static RemoteTransactionId New() => new(Guid.NewGuid());

    public static RemoteTransactionId Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != 36 || !Guid.TryParseExact(value, "D", out var parsed))
        {
            throw new FormatException("Remote transaction ID must use the canonical UUID form.");
        }

        return new RemoteTransactionId(parsed);
    }

    public override string ToString() => Value.ToString("D");
}

public sealed record RemoteHelperResult(int? ExitStatus, string? ExitSignal, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitStatus == 0;
}
