using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using CertBaton.Application.Remote;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace CertBaton.Remote.Ssh;

internal sealed class SshNetSession : IRemoteSshSession
{
    private const int BufferSize = 64 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private readonly RemoteSshConnectionOptions _options;
    private readonly SftpClient _sftpClient;
    private readonly SshClient _sshClient;
    private readonly PrivateKeyFile _sftpKeyFile;
    private readonly PrivateKeyFile _sshKeyFile;
    private readonly Stream _sftpKeyStream;
    private readonly Stream _sshKeyStream;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _disposed;

    internal SshNetSession(
        RemoteSshConnectionOptions options,
        SftpClient sftpClient,
        SshClient sshClient,
        PrivateKeyFile sftpKeyFile,
        PrivateKeyFile sshKeyFile,
        Stream sftpKeyStream,
        Stream sshKeyStream)
    {
        _options = options;
        _sftpClient = sftpClient;
        _sshClient = sshClient;
        _sftpKeyFile = sftpKeyFile;
        _sshKeyFile = sshKeyFile;
        _sftpKeyStream = sftpKeyStream;
        _sshKeyStream = sshKeyStream;
    }

    public RemoteSshEndpoint Endpoint => _options.Endpoint;

    public async Task<bool> FileExistsAsync(RemotePosixPath path, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await _sftpClient.ExistsAsync(path.Value, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task UploadFileAsync(
        RemotePosixPath path,
        Stream content,
        RemoteWriteMode writeMode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(content);
        if (!content.CanRead)
        {
            throw new ArgumentException("Upload content stream must be readable.", nameof(content));
        }

        if (!Enum.IsDefined(writeMode))
        {
            throw new ArgumentOutOfRangeException(nameof(writeMode), writeMode, "Unknown remote write mode.");
        }

        ValidateKnownLength(content);
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (writeMode == RemoteWriteMode.CreateNew)
            {
                await UploadCreateNewAsync(path, content, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await UploadAtomicReplaceAsync(path, content, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<byte[]> ReadFileAsync(RemotePosixPath path, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await ValidateRemoteFileSizeAsync(path, cancellationToken).ConfigureAwait(false);
            await using var remote = await _sftpClient.OpenAsync(
                path.Value,
                FileMode.Open,
                FileAccess.Read,
                cancellationToken).ConfigureAwait(false);
            using var destination = new MemoryStream();
            await CopyFromRemoteBoundedAsync(remote, destination, "read", cancellationToken).ConfigureAwait(false);
            return destination.ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RemoteFileSha256> ComputeSha256Async(RemotePosixPath path, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await ValidateRemoteFileSizeAsync(path, cancellationToken).ConfigureAwait(false);
            await using var remote = await _sftpClient.OpenAsync(
                path.Value,
                FileMode.Open,
                FileAccess.Read,
                cancellationToken).ConfigureAwait(false);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
            long total = 0;
            try
            {
                int bytesRead;
                while ((bytesRead = await remote.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken).ConfigureAwait(false)) != 0)
                {
                    total = CheckedTotal(total, bytesRead, "hash");
                    hash.AppendData(buffer, 0, bytesRead);
                }

                var digest = hash.GetHashAndReset();
                return new RemoteFileSha256(Convert.ToHexStringLower(digest), total);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer.AsSpan(0, BufferSize));
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RemoveFileAsync(
        RemotePosixPath path,
        MissingFileBehavior missingFileBehavior,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (!Enum.IsDefined(missingFileBehavior))
        {
            throw new ArgumentOutOfRangeException(
                nameof(missingFileBehavior),
                missingFileBehavior,
                "Unknown missing-file behavior.");
        }

        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            try
            {
                await _sftpClient.DeleteFileAsync(path.Value, cancellationToken).ConfigureAwait(false);
            }
            catch (SftpPathNotFoundException) when (missingFileBehavior == MissingFileBehavior.Ignore)
            {
                // The requested postcondition is already true.
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RemoteHelperResult> InvokeHelperAsync(
        RemoteHelperVerbV1 verb,
        RemoteTransactionId transactionId,
        CancellationToken cancellationToken)
    {
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var commandText = RemoteHelperCommand.Build(verb, transactionId);
            using var command = _sshClient.CreateCommand(commandText, StrictUtf8);
            command.CommandTimeout = _options.OperationTimeout;
            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            var executionTask = command.ExecuteAsync(linkedCancellation.Token);
            var standardOutputTask = ReadHelperOutputAsync(
                command.OutputStream,
                "helper standard output",
                linkedCancellation,
                linkedCancellation.Token);
            var standardErrorTask = ReadHelperOutputAsync(
                command.ExtendedOutputStream,
                "helper standard error",
                linkedCancellation,
                linkedCancellation.Token);

            try
            {
                await executionTask.ConfigureAwait(false);
                var output = await standardOutputTask.ConfigureAwait(false);
                var error = await standardErrorTask.ConfigureAwait(false);
                return new RemoteHelperResult(command.ExitStatus, command.ExitSignal, output, error);
            }
            catch
            {
                linkedCancellation.Cancel();
                await ObserveFailureAsync(executionTask).ConfigureAwait(false);
                await ObserveFailureAsync(standardOutputTask).ConfigureAwait(false);
                await ObserveFailureAsync(standardErrorTask).ConfigureAwait(false);

                var limitException = FindLimitException(standardOutputTask) ?? FindLimitException(standardErrorTask);
                if (limitException is not null)
                {
                    throw limitException;
                }

                throw;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            _sshClient.Dispose();
            _sftpClient.Dispose();
            _sshKeyFile.Dispose();
            _sftpKeyFile.Dispose();
            _sshKeyStream.Dispose();
            _sftpKeyStream.Dispose();
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }

    private async Task UploadCreateNewAsync(RemotePosixPath path, Stream content, CancellationToken cancellationToken)
    {
        var created = false;
        try
        {
            await using var remote = await _sftpClient.OpenAsync(
                path.Value,
                FileMode.CreateNew,
                FileAccess.Write,
                cancellationToken).ConfigureAwait(false);
            created = true;
            await CopyToRemoteBoundedAsync(content, remote, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (created)
            {
                await TryDeleteAsync(path.Value).ConfigureAwait(false);
            }

            throw;
        }
    }

    private async Task UploadAtomicReplaceAsync(RemotePosixPath path, Stream content, CancellationToken cancellationToken)
    {
        var temporaryPath = CreateTemporarySibling(path);
        var created = false;
        try
        {
            await using (var remote = await _sftpClient.OpenAsync(
                temporaryPath.Value,
                FileMode.CreateNew,
                FileAccess.Write,
                cancellationToken).ConfigureAwait(false))
            {
                created = true;
                await CopyToRemoteBoundedAsync(content, remote, cancellationToken).ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();
            await Task.Run(
                () => _sftpClient.RenameFile(temporaryPath.Value, path.Value, isPosix: true),
                cancellationToken).ConfigureAwait(false);
            created = false;
        }
        catch
        {
            if (created)
            {
                await TryDeleteAsync(temporaryPath.Value).ConfigureAwait(false);
            }

            throw;
        }
    }

    private async Task CopyToRemoteBoundedAsync(Stream source, Stream destination, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        long total = 0;
        try
        {
            int bytesRead;
            while ((bytesRead = await source.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken).ConfigureAwait(false)) != 0)
            {
                total = CheckedTotal(total, bytesRead, "upload");
                await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
            }

            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, BufferSize));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task CopyFromRemoteBoundedAsync(
        Stream source,
        Stream destination,
        string operation,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        long total = 0;
        try
        {
            int bytesRead;
            while ((bytesRead = await source.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken).ConfigureAwait(false)) != 0)
            {
                total = CheckedTotal(total, bytesRead, operation);
                await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, BufferSize));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task<string> ReadHelperOutputAsync(
        Stream source,
        string operation,
        CancellationTokenSource linkedCancellation,
        CancellationToken callerCancellation)
    {
        using var destination = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        long total = 0;
        try
        {
            int bytesRead;
            while ((bytesRead = await source.ReadAsync(buffer.AsMemory(0, BufferSize), callerCancellation).ConfigureAwait(false)) != 0)
            {
                total += bytesRead;
                if (total > _options.MaximumHelperOutputBytes)
                {
                    linkedCancellation.Cancel();
                    throw new RemoteTransferLimitExceededException(operation, _options.MaximumHelperOutputBytes);
                }

                await destination.WriteAsync(buffer.AsMemory(0, bytesRead), callerCancellation).ConfigureAwait(false);
            }

            try
            {
                return StrictUtf8.GetString(destination.GetBuffer(), 0, checked((int)destination.Length));
            }
            catch (DecoderFallbackException exception)
            {
                throw new InvalidDataException($"Remote {operation} was not valid UTF-8.", exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, BufferSize));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task ValidateRemoteFileSizeAsync(RemotePosixPath path, CancellationToken cancellationToken)
    {
        var attributes = await _sftpClient.GetAttributesAsync(path.Value, cancellationToken).ConfigureAwait(false);
        if (attributes.Size > _options.MaximumTransferBytes)
        {
            throw new RemoteTransferLimitExceededException("read", _options.MaximumTransferBytes);
        }
    }

    private long CheckedTotal(long total, int increment, string operation)
    {
        if (total > _options.MaximumTransferBytes - increment)
        {
            throw new RemoteTransferLimitExceededException(operation, _options.MaximumTransferBytes);
        }

        return total + increment;
    }

    private void ValidateKnownLength(Stream content)
    {
        if (!content.CanSeek)
        {
            return;
        }

        var remaining = content.Length - content.Position;
        if (remaining < 0)
        {
            throw new ArgumentException("Upload stream position exceeds its length.", nameof(content));
        }

        if (remaining > _options.MaximumTransferBytes)
        {
            throw new RemoteTransferLimitExceededException("upload", _options.MaximumTransferBytes);
        }
    }

    private async Task EnterAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (Volatile.Read(ref _disposed) != 0)
        {
            _gate.Release();
            throw new ObjectDisposedException(nameof(SshNetSession));
        }
    }

    private async Task TryDeleteAsync(string path)
    {
        try
        {
            await _sftpClient.DeleteFileAsync(path, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is SftpPathNotFoundException or SshException or ObjectDisposedException)
        {
            // Cleanup is best effort and must not conceal the original transfer failure.
        }
    }

    private static RemotePosixPath CreateTemporarySibling(RemotePosixPath path)
    {
        const int maximumPrefixLength = 200;
        var prefix = path.FileName.Value.Length <= maximumPrefixLength
            ? path.FileName.Value
            : path.FileName.Value[..maximumPrefixLength];
        var temporaryName = new RemotePathSegment($"{prefix}.certbaton-{Guid.NewGuid():N}.tmp");
        return path.Segments.Count == 1
            ? RemotePosixPath.Parse('/' + temporaryName.Value)
            : path.Parent.Combine(temporaryName);
    }

    private static async Task ObserveFailureAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch
        {
            // The initiating exception is propagated by the caller after all tasks are observed.
        }
    }

    private static RemoteTransferLimitExceededException? FindLimitException(Task task) =>
        task.Exception?.Flatten().InnerExceptions.OfType<RemoteTransferLimitExceededException>().FirstOrDefault();
}
