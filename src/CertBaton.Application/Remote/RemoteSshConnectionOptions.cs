namespace CertBaton.Application.Remote;

public sealed record RemoteSshConnectionOptions
{
    public static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan DefaultOperationTimeout = TimeSpan.FromSeconds(60);
    public const long DefaultMaximumTransferBytes = 4 * 1024 * 1024;
    public const int DefaultMaximumHelperOutputBytes = 64 * 1024;
    public const long AbsoluteMaximumTransferBytes = 64 * 1024 * 1024;
    public const int AbsoluteMaximumHelperOutputBytes = 1024 * 1024;

    public RemoteSshConnectionOptions(
        RemoteSshEndpoint endpoint,
        SshHostKeyPin hostKeyPin,
        TimeSpan? connectTimeout = null,
        TimeSpan? operationTimeout = null,
        long maximumTransferBytes = DefaultMaximumTransferBytes,
        int maximumHelperOutputBytes = DefaultMaximumHelperOutputBytes)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(hostKeyPin);

        if (!string.Equals(endpoint.Host, hostKeyPin.Host, StringComparison.Ordinal) || endpoint.Port != hostKeyPin.Port)
        {
            throw new ArgumentException("Host-key pin must match the normalized SSH endpoint host and port.", nameof(hostKeyPin));
        }

        Endpoint = endpoint;
        HostKeyPin = hostKeyPin;
        ConnectTimeout = ValidateTimeout(connectTimeout ?? DefaultConnectTimeout, nameof(connectTimeout));
        OperationTimeout = ValidateTimeout(operationTimeout ?? DefaultOperationTimeout, nameof(operationTimeout));

        if (maximumTransferBytes is < 1 or > AbsoluteMaximumTransferBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumTransferBytes),
                maximumTransferBytes,
                $"Transfer limit must be between 1 and {AbsoluteMaximumTransferBytes} bytes.");
        }

        if (maximumHelperOutputBytes is < 1 or > AbsoluteMaximumHelperOutputBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumHelperOutputBytes),
                maximumHelperOutputBytes,
                $"Helper output limit must be between 1 and {AbsoluteMaximumHelperOutputBytes} bytes.");
        }

        MaximumTransferBytes = maximumTransferBytes;
        MaximumHelperOutputBytes = maximumHelperOutputBytes;
    }

    public RemoteSshEndpoint Endpoint { get; }

    public SshHostKeyPin HostKeyPin { get; }

    public TimeSpan ConnectTimeout { get; }

    public TimeSpan OperationTimeout { get; }

    public long MaximumTransferBytes { get; }

    public int MaximumHelperOutputBytes { get; }

    private static TimeSpan ValidateTimeout(TimeSpan timeout, string parameterName)
    {
        if (timeout < TimeSpan.FromSeconds(1) || timeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(parameterName, timeout, "Timeout must be between one second and five minutes.");
        }

        return timeout;
    }
}
