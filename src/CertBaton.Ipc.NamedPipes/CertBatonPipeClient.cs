using System.IO.Pipes;
using System.Security.Principal;
using CertBaton.Contracts;

namespace CertBaton.Ipc.NamedPipes;

public sealed class CertBatonPipeClient
{
    private readonly IpcClientOptions options;
    private readonly IpcFrameCodec codec;
    private readonly TimeProvider timeProvider;

    public CertBatonPipeClient(
        IpcClientOptions? options = null,
        IpcFrameCodec? codec = null,
        TimeProvider? timeProvider = null)
    {
        this.options = options ?? new IpcClientOptions();
        this.codec = codec ?? new IpcFrameCodec();
        this.timeProvider = timeProvider ?? TimeProvider.System;

        if (string.IsNullOrWhiteSpace(this.options.PipeName))
        {
            throw new ArgumentException("The pipe name cannot be empty.", nameof(options));
        }

        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(
            this.options.ConnectTimeout,
            TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            this.options.ConnectTimeout,
            IpcProtocol.MaximumRequestHorizon);

        if (this.options.DevelopmentServerProcessId <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "A development server process identifier must be positive.");
        }
    }

    public Task<IpcResponse> GetHealthAsync(CancellationToken cancellationToken = default) =>
        SendAsync(
            IpcRequest.CreateHealth(timeProvider, options.ConnectTimeout),
            cancellationToken);

    public async Task<IpcResponse> SendAsync(
        IpcRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ConnectTimeout);

        using var pipe = new NamedPipeClientStream(
            ".",
            options.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            TokenImpersonationLevel.Identification);

        try
        {
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            PipeServerAuthenticator.Authenticate(pipe, options.DevelopmentServerProcessId);
            await codec.WriteAsync(pipe, request, timeout.Token).ConfigureAwait(false);
            var response = await codec.ReadAsync<IpcResponse>(pipe, timeout.Token).ConfigureAwait(false);

            if (response.ProtocolVersion != IpcProtocol.CurrentVersion)
            {
                throw new IpcProtocolException(
                    $"The service returned protocol version {response.ProtocolVersion}; this client supports version {IpcProtocol.CurrentVersion}.");
            }

            if (response.RequestId != request.RequestId)
            {
                throw new IpcProtocolException("The service response did not match the request identifier.");
            }

            if (response.Success != (response.Result is not null) ||
                response.Success == (response.Error is not null))
            {
                throw new IpcProtocolException("The service response contained an inconsistent success result.");
            }

            return response;
        }
        catch (OperationCanceledException) when (
            timeout.IsCancellationRequested &&
            !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"The CertBaton service did not respond within {options.ConnectTimeout.TotalSeconds:0.#} seconds.");
        }
    }
}
