using System.IO.Pipes;
using System.Security.Principal;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;

namespace CertBaton.ProtocolIntegrationTests;

[TestClass]
public sealed class NamedPipeProtocolTests
{
    [TestMethod]
    public async Task HealthRequestRoundTripsAcrossAuthenticatedPipe()
    {
        var pipeName = $"CertBaton.Tests.{Guid.NewGuid():N}";
        var startedAtUtc = DateTimeOffset.UtcNow;
        string? observedClientSid = null;
        TokenImpersonationLevel? observedImpersonationLevel = null;
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = CreateServer(pipeName);
        var serverTask = server.RunAsync(
            (request, identity, cancellationToken) =>
            {
                observedClientSid = identity.UserSid;
                observedImpersonationLevel = identity.ImpersonationLevel;
                _ = cancellationToken;
                return ValueTask.FromResult(
                    IpcResponse.Succeeded(
                        request.RequestId,
                        new HealthSnapshot(
                            "healthy",
                            "test",
                            startedAtUtc,
                            DateTimeOffset.UtcNow)));
            },
            serverCancellation.Token);

        var client = CreateClient(pipeName);
        var response = await client.GetHealthAsync(serverCancellation.Token);

        Assert.IsTrue(response.Success);
        Assert.IsNotNull(response.Result);
        Assert.AreEqual("healthy", response.Result.Status);
        Assert.AreEqual("test", response.Result.ServiceVersion);
        Assert.AreEqual(
            WindowsIdentity.GetCurrent().User?.Value,
            observedClientSid);
        Assert.AreEqual(
            TokenImpersonationLevel.Identification,
            observedImpersonationLevel);

        await StopServerAsync(serverCancellation, serverTask);
    }

    [TestMethod]
    public async Task UnsupportedVersionIsRejectedBeforeHandlerRuns()
    {
        var pipeName = $"CertBaton.Tests.{Guid.NewGuid():N}";
        var handlerCalled = false;
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = CreateServer(pipeName);
        var serverTask = server.RunAsync(
            (request, identity, cancellationToken) =>
            {
                _ = request;
                _ = identity;
                _ = cancellationToken;
                handlerCalled = true;
                return ValueTask.FromResult(
                    IpcResponse.Failed(Guid.Empty, "unexpected", "The handler should not run."));
            },
            serverCancellation.Token);

        var now = DateTimeOffset.UtcNow;
        var request = new IpcRequest(
            IpcProtocol.CurrentVersion + 1,
            Guid.NewGuid(),
            IpcProtocol.HealthMethod,
            now,
            now.AddSeconds(3));

        var client = CreateClient(pipeName);
        var response = await client.SendAsync(request, serverCancellation.Token);

        Assert.IsFalse(response.Success);
        Assert.AreEqual("protocol_version_unsupported", response.Error?.Code);
        Assert.IsFalse(handlerCalled);

        await StopServerAsync(serverCancellation, serverTask);
    }

    [TestMethod]
    public async Task UnreasonableDeadlineIsRejectedBeforeHandlerRuns()
    {
        var pipeName = $"CertBaton.Tests.{Guid.NewGuid():N}";
        var handlerCalled = false;
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = CreateServer(pipeName);
        var serverTask = server.RunAsync(
            (request, identity, cancellationToken) =>
            {
                _ = request;
                _ = identity;
                _ = cancellationToken;
                handlerCalled = true;
                return ValueTask.FromResult(
                    IpcResponse.Failed(Guid.Empty, "unexpected", "The handler should not run."));
            },
            serverCancellation.Token);

        var now = DateTimeOffset.UtcNow;
        var request = new IpcRequest(
            IpcProtocol.CurrentVersion,
            Guid.NewGuid(),
            IpcProtocol.HealthMethod,
            now,
            now.AddMinutes(10));

        var client = CreateClient(pipeName);
        var response = await client.SendAsync(request, serverCancellation.Token);

        Assert.IsFalse(response.Success);
        Assert.AreEqual("invalid_deadline", response.Error?.Code);
        Assert.IsFalse(handlerCalled);

        await StopServerAsync(serverCancellation, serverTask);
    }

    [TestMethod]
    public async Task StalledClientReleasesItsConnectionSlot()
    {
        var pipeName = $"CertBaton.Tests.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = new CertBatonPipeServer(
            new IpcServerOptions
            {
                PipeName = pipeName,
                MaximumConcurrentClients = 1,
                ClientRequestTimeout = TimeSpan.FromMilliseconds(500),
                SecurityProfile = PipeServerSecurityProfile.CurrentUserDevelopment,
            });
        var serverTask = server.RunAsync(
            (request, identity, cancellationToken) =>
            {
                _ = identity;
                _ = cancellationToken;
                return ValueTask.FromResult(
                    IpcResponse.Succeeded(
                        request.RequestId,
                        new HealthSnapshot(
                            "healthy",
                            "test",
                            DateTimeOffset.UtcNow,
                            DateTimeOffset.UtcNow)));
            },
            serverCancellation.Token);

        using (var stalledClient = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification))
        {
            await stalledClient.ConnectAsync(serverCancellation.Token);
            await Task.Delay(TimeSpan.FromMilliseconds(1200), serverCancellation.Token);

            var response = await CreateClient(pipeName).GetHealthAsync(serverCancellation.Token);

            Assert.IsTrue(response.Success);
            Assert.AreEqual("healthy", response.Result?.Status);
        }

        await StopServerAsync(serverCancellation, serverTask);
    }

    [TestMethod]
    public async Task RequestDeadlineCancelsHandlerAndReturnsError()
    {
        var pipeName = $"CertBaton.Tests.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = CreateServer(pipeName);
        var serverTask = server.RunAsync(
            async (request, identity, cancellationToken) =>
            {
                _ = request;
                _ = identity;
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                return IpcResponse.Failed(Guid.Empty, "unexpected", "The handler should have been cancelled.");
            },
            serverCancellation.Token);

        var now = DateTimeOffset.UtcNow;
        var request = new IpcRequest(
            IpcProtocol.CurrentVersion,
            Guid.NewGuid(),
            IpcProtocol.HealthMethod,
            now,
            now.AddMilliseconds(500));

        var response = await CreateClient(pipeName).SendAsync(request, serverCancellation.Token);

        Assert.IsFalse(response.Success);
        Assert.AreEqual("deadline_exceeded", response.Error?.Code);

        await StopServerAsync(serverCancellation, serverTask);
    }

    [TestMethod]
    public async Task NonCooperativeHandlerCannotHoldClientSlotOrReturnLateSuccess()
    {
        var pipeName = $"CertBaton.Tests.{Guid.NewGuid():N}";
        var callCount = 0;
        var releaseFirstHandler = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var firstHandlerFinished = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = new CertBatonPipeServer(
            new IpcServerOptions
            {
                PipeName = pipeName,
                MaximumConcurrentClients = 1,
                SecurityProfile = PipeServerSecurityProfile.CurrentUserDevelopment,
            });
        var serverTask = server.RunAsync(
            async (request, identity, cancellationToken) =>
            {
                _ = identity;
                _ = cancellationToken;
                if (Interlocked.Increment(ref callCount) == 1)
                {
                    await releaseFirstHandler.Task;
                    firstHandlerFinished.SetResult();
                }

                return IpcResponse.Succeeded(
                    request.RequestId,
                    new HealthSnapshot(
                        "healthy",
                        "test",
                        DateTimeOffset.UtcNow,
                        DateTimeOffset.UtcNow));
            },
            serverCancellation.Token);

        var now = DateTimeOffset.UtcNow;
        var firstRequest = new IpcRequest(
            IpcProtocol.CurrentVersion,
            Guid.NewGuid(),
            IpcProtocol.HealthMethod,
            now,
            now.AddMilliseconds(750));

        try
        {
            var firstResponse = await CreateClient(pipeName)
                .SendAsync(firstRequest, serverCancellation.Token);

            Assert.IsFalse(firstResponse.Success);
            Assert.AreEqual("deadline_exceeded", firstResponse.Error?.Code);
            Assert.IsFalse(firstHandlerFinished.Task.IsCompleted);

            var secondResponse = await CreateClient(pipeName)
                .GetHealthAsync(serverCancellation.Token);

            Assert.IsTrue(secondResponse.Success);
            Assert.AreEqual("healthy", secondResponse.Result?.Status);
            Assert.IsFalse(firstHandlerFinished.Task.IsCompleted);
        }
        finally
        {
            releaseFirstHandler.TrySetResult();
            await firstHandlerFinished.Task.WaitAsync(TimeSpan.FromSeconds(3));
            await StopServerAsync(serverCancellation, serverTask);
        }
    }

    [TestMethod]
    public async Task PipeNameSquatterIsRejectedBeforeRequestIsSent()
    {
        var pipeName = $"CertBaton.Tests.{Guid.NewGuid():N}";
        using var testCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var squatter = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);

        var squatterTask = Task.Run(
            async () =>
            {
                try
                {
                    await squatter.WaitForConnectionAsync(testCancellation.Token);
                    var buffer = new byte[1];
                    return await squatter.ReadAsync(buffer, testCancellation.Token);
                }
                catch (IOException)
                {
                    // A client that authenticates and immediately closes can
                    // race the server's connection completion. Either outcome
                    // proves that no request byte reached the squatter.
                    return 0;
                }
            },
            testCancellation.Token);

        var mismatchedProcessId = Environment.ProcessId == int.MaxValue
            ? 1
            : Environment.ProcessId + 1;
        var client = new CertBatonPipeClient(
            new IpcClientOptions
            {
                PipeName = pipeName,
                ConnectTimeout = TimeSpan.FromSeconds(3),
                DevelopmentServerProcessId = mismatchedProcessId,
            });

        await Assert.ThrowsExactlyAsync<PipeServerAuthenticationException>(
            async () => await client.GetHealthAsync(testCancellation.Token));
        Assert.AreEqual(0, await squatterTask);
    }

    private static CertBatonPipeServer CreateServer(string pipeName) =>
        new(
            new IpcServerOptions
            {
                PipeName = pipeName,
                MaximumConcurrentClients = 2,
                SecurityProfile = PipeServerSecurityProfile.CurrentUserDevelopment,
            });

    private static CertBatonPipeClient CreateClient(string pipeName) =>
        new(
            new IpcClientOptions
            {
                PipeName = pipeName,
                ConnectTimeout = TimeSpan.FromSeconds(5),
                DevelopmentServerProcessId = Environment.ProcessId,
            });

    private static async Task StopServerAsync(
        CancellationTokenSource cancellation,
        Task serverTask)
    {
        await cancellation.CancelAsync();
        await serverTask.WaitAsync(TimeSpan.FromSeconds(3));
    }
}
