using System.IO.Pipes;
using CertBaton.Contracts;

namespace CertBaton.Ipc.NamedPipes;

public sealed class CertBatonPipeServer
{
    private readonly IpcServerOptions options;
    private readonly IpcFrameCodec codec;
    private readonly TimeProvider timeProvider;

    public CertBatonPipeServer(
        IpcServerOptions? options = null,
        IpcFrameCodec? codec = null,
        TimeProvider? timeProvider = null)
    {
        this.options = options ?? new IpcServerOptions();
        this.codec = codec ?? new IpcFrameCodec();
        this.timeProvider = timeProvider ?? TimeProvider.System;

        if (string.IsNullOrWhiteSpace(this.options.PipeName))
        {
            throw new ArgumentException("The pipe name cannot be empty.", nameof(options));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            this.options.MaximumConcurrentClients);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(
            this.options.ClientRequestTimeout,
            TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            this.options.ClientRequestTimeout,
            IpcProtocol.MaximumRequestHorizon);
    }

    public async Task RunAsync(
        Func<IpcRequest, PipeClientIdentity, CancellationToken, ValueTask<IpcResponse>> handler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);

        var activeClients = new List<Task>();
        using var concurrency = new SemaphoreSlim(options.MaximumConcurrentClients);
        var firstInstance = true;

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);

                NamedPipeServerStream? pipe = null;
                var slotTransferredToClient = false;
                try
                {
                    pipe = CreatePipe(firstInstance);
                    firstInstance = false;
                    await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                    var connectedPipe = pipe;
                    pipe = null;
                    activeClients.Add(
                        HandleClientAndReleaseAsync(
                            connectedPipe,
                            handler,
                            concurrency,
                            cancellationToken));
                    slotTransferredToClient = true;

                    await RemoveCompletedClientsAsync(activeClients).ConfigureAwait(false);
                }
                catch
                {
                    pipe?.Dispose();
                    if (!slotTransferredToClient)
                    {
                        concurrency.Release();
                    }

                    throw;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            await Task.WhenAll(activeClients).ConfigureAwait(false);
        }
    }

    private NamedPipeServerStream CreatePipe(bool firstInstance)
    {
        var pipeOptions = PipeOptions.Asynchronous | PipeOptions.WriteThrough;
        if (firstInstance)
        {
            pipeOptions |= PipeOptions.FirstPipeInstance;
        }

        return NamedPipeServerStreamAcl.Create(
            options.PipeName,
            PipeDirection.InOut,
            options.MaximumConcurrentClients,
            PipeTransmissionMode.Byte,
            pipeOptions,
            IpcProtocol.MaximumFrameBytes,
            IpcProtocol.MaximumFrameBytes,
            PipeSecurityFactory.CreateHealthOnlySecurity(options.SecurityProfile),
            HandleInheritability.None,
            0);
    }

    private async Task HandleClientAndReleaseAsync(
        NamedPipeServerStream pipe,
        Func<IpcRequest, PipeClientIdentity, CancellationToken, ValueTask<IpcResponse>> handler,
        SemaphoreSlim concurrency,
        CancellationToken cancellationToken)
    {
        using var clientDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        clientDeadline.CancelAfter(options.ClientRequestTimeout);

        try
        {
            using (pipe)
            {
                var identity = PipeClientIdentityReader.Read(pipe);
                var request = await codec.ReadAsync<IpcRequest>(pipe, clientDeadline.Token).ConfigureAwait(false);
                var response = await DispatchAsync(request, identity, handler, clientDeadline.Token).ConfigureAwait(false);
                await codec.WriteAsync(pipe, response, clientDeadline.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (OperationCanceledException) when (clientDeadline.IsCancellationRequested)
        {
            // Slow or stalled clients lose their slot without affecting the service.
        }
        catch (IOException)
        {
            // A disconnected local client is not a service failure.
        }
        catch (IpcProtocolException)
        {
            // Frames that cannot be trusted are closed without a response.
        }
        catch (UnauthorizedAccessException)
        {
            // The pipe DACL and token check fail closed.
        }
        finally
        {
            concurrency.Release();
        }
    }

    private static async Task RemoveCompletedClientsAsync(List<Task> activeClients)
    {
        for (var index = activeClients.Count - 1; index >= 0; index--)
        {
            var task = activeClients[index];
            if (!task.IsCompleted)
            {
                continue;
            }

            activeClients.RemoveAt(index);
            await task.ConfigureAwait(false);
        }
    }

    private async ValueTask<IpcResponse> DispatchAsync(
        IpcRequest request,
        PipeClientIdentity identity,
        Func<IpcRequest, PipeClientIdentity, CancellationToken, ValueTask<IpcResponse>> handler,
        CancellationToken cancellationToken)
    {
        if (request.RequestId == Guid.Empty)
        {
            return IpcResponse.Failed(Guid.Empty, "invalid_request", "A non-empty request identifier is required.");
        }

        if (request.ProtocolVersion != IpcProtocol.CurrentVersion)
        {
            return IpcResponse.Failed(
                request.RequestId,
                "protocol_version_unsupported",
                $"Protocol version {request.ProtocolVersion} is not supported.");
        }

        if (string.IsNullOrWhiteSpace(request.Method) || request.Method.Length > 64)
        {
            return IpcResponse.Failed(
                request.RequestId,
                "invalid_request",
                "A valid method name is required.");
        }

        var now = timeProvider.GetUtcNow();
        if (request.DeadlineUtc <= now)
        {
            return IpcResponse.Failed(
                request.RequestId,
                "deadline_exceeded",
                "The request deadline has elapsed.");
        }

        if (request.SentAtUtc > now.Add(IpcProtocol.ClockSkewAllowance) ||
            request.SentAtUtc < now.Subtract(IpcProtocol.MaximumRequestHorizon) ||
            request.DeadlineUtc <= request.SentAtUtc ||
            request.DeadlineUtc > now.Add(IpcProtocol.MaximumRequestHorizon))
        {
            return IpcResponse.Failed(
                request.RequestId,
                "invalid_deadline",
                "The request timestamps are outside the permitted local IPC window.");
        }

        try
        {
            var remaining = request.DeadlineUtc - timeProvider.GetUtcNow();
            if (remaining <= TimeSpan.Zero)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "deadline_exceeded",
                    "The request deadline elapsed before execution.");
            }

            using var requestDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            requestDeadline.CancelAfter(remaining);
            var handlerTask = handler(request, identity, requestDeadline.Token).AsTask();

            try
            {
                return await handlerTask
                    .WaitAsync(requestDeadline.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                requestDeadline.IsCancellationRequested &&
                !cancellationToken.IsCancellationRequested)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    "deadline_exceeded",
                    "The request deadline elapsed during execution.");
            }
            finally
            {
                if (!handlerTask.IsCompleted)
                {
                    _ = ObserveDetachedHandlerAsync(handlerTask);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return IpcResponse.Failed(
                request.RequestId,
                "internal_error",
                "The service could not complete the request.");
        }
    }

    private static async Task ObserveDetachedHandlerAsync(Task<IpcResponse> handlerTask)
    {
        try
        {
            _ = await handlerTask.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // A handler that ignores cancellation is detached from IPC. Its
            // eventual failure is observed so it cannot become unobserved.
        }
    }
}
