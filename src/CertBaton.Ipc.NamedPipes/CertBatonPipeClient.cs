using System.IO.Pipes;
using System.Security.Cryptography;
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

    public Task<IpcResponse> GetLatestSimulationAsync(
        CancellationToken cancellationToken = default) =>
        SendAsync(
            IpcRequest.CreateSimulationLatest(
                timeProvider,
                options.ConnectTimeout),
            cancellationToken);

    public Task<IpcResponse> StartSimulationAsync(
        Guid idempotencyKey,
        string? failureStage = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            IpcRequest.CreateSimulationStart(
                timeProvider,
                idempotencyKey,
                failureStage,
                options.ConnectTimeout),
            cancellationToken);

    public Task<IpcResponse> ProbeVaultAsync(
        CancellationToken cancellationToken = default) =>
        SendAsync(
            IpcRequest.CreateVaultProbe(
                timeProvider,
                options.ConnectTimeout),
            cancellationToken);

    public async Task<IpcResponse> ImportSshPrivateKeyAsync(
        ReadOnlyMemory<byte> privateKey,
        CancellationToken cancellationToken = default)
    {
        var request = IpcRequest.CreateCredentialImportSshPrivateKey(
            timeProvider,
            privateKey.Span,
            options.ConnectTimeout);
        try
        {
            return await SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            if (request.CredentialPayload?.Secret is { } secret)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
    }

    public Task<IpcResponse> EnrollTargetAsync(
        TargetEnrollmentPayload payload,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            IpcRequest.CreateTargetEnrollment(
                timeProvider,
                payload,
                options.ConnectTimeout),
            cancellationToken);

    public Task<IpcResponse> ListTargetsAsync(
        CancellationToken cancellationToken = default) =>
        SendAsync(
            IpcRequest.CreateTargetList(
                timeProvider,
                options.ConnectTimeout),
            cancellationToken);

    public Task<IpcResponse> StartRenewalAsync(
        Guid targetId,
        Guid idempotencyKey,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            IpcRequest.CreateRenewalStart(
                timeProvider,
                new RenewalStartPayload(targetId, idempotencyKey),
                options.ConnectTimeout),
            cancellationToken);

    public Task<IpcResponse> GetRenewalAsync(
        Guid operationId,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            IpcRequest.CreateRenewalGet(
                timeProvider,
                new RenewalQueryPayload(operationId),
                options.ConnectTimeout),
            cancellationToken);

    public async Task<IpcResponse> SendAsync(
        IpcRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!request.TryValidateMethodPayload(out var requestError))
        {
            throw new IpcProtocolException(
                $"The request contained an invalid method payload: {requestError}");
        }

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

            if (!response.TryValidateForMethod(request.Method, out var responseError))
            {
                throw new IpcProtocolException(
                    $"The service response was invalid: {responseError}");
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
