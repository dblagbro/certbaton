namespace CertBaton.Application.Remote;

public enum RemoteWriteMode
{
    CreateNew = 0,
    AtomicReplace = 1,
}

public enum MissingFileBehavior
{
    Fail = 0,
    Ignore = 1,
}

public readonly record struct RemoteFileSha256(string HexDigest, long BytesHashed);

public interface IRemoteSshSessionFactory
{
    ValueTask<IRemoteSshSession> ConnectAsync(
        RemoteSshConnectionOptions options,
        RemotePrivateKeyMaterial privateKey,
        CancellationToken cancellationToken);
}

public interface IRemoteSshSession : IAsyncDisposable
{
    RemoteSshEndpoint Endpoint { get; }

    Task<bool> FileExistsAsync(RemotePosixPath path, CancellationToken cancellationToken);

    Task UploadFileAsync(
        RemotePosixPath path,
        Stream content,
        RemoteWriteMode writeMode,
        CancellationToken cancellationToken);

    Task<byte[]> ReadFileAsync(RemotePosixPath path, CancellationToken cancellationToken);

    Task<RemoteFileSha256> ComputeSha256Async(RemotePosixPath path, CancellationToken cancellationToken);

    Task RemoveFileAsync(
        RemotePosixPath path,
        MissingFileBehavior missingFileBehavior,
        CancellationToken cancellationToken);

    Task<RemoteHelperResult> InvokeHelperAsync(
        RemoteHelperVerbV1 verb,
        RemoteTransactionId transactionId,
        CancellationToken cancellationToken);
}

public sealed class RemoteTransferLimitExceededException : IOException
{
    public RemoteTransferLimitExceededException(string operation, long maximumBytes)
        : base($"Remote {operation} exceeded the configured {maximumBytes}-byte limit.")
    {
        MaximumBytes = maximumBytes;
    }

    public long MaximumBytes { get; }
}
