using CertBaton.Contracts;
using CertBaton.Desktop;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class MainWindowViewModelTests
{
    private static readonly DateTimeOffset runStart =
        new(2026, 7, 29, 14, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public async Task LogicalHealthFailureClearsPreviouslyDisplayedServiceDetails()
    {
        var responses = new Queue<IpcResponse>(
        [
            IpcResponse.Succeeded(
                Guid.NewGuid(),
                new HealthSnapshot(
                    "healthy",
                    "1.2.3",
                    new DateTimeOffset(2026, 7, 29, 10, 0, 0, TimeSpan.Zero),
                    new DateTimeOffset(2026, 7, 29, 10, 1, 0, TimeSpan.Zero))),
            IpcResponse.Failed(
                Guid.NewGuid(),
                "service.degraded",
                "The service could not complete its health check."),
        ]);
        var viewModel = new MainWindowViewModel(
            _ => Task.FromResult(responses.Dequeue()));

        await viewModel.RefreshCommand.ExecuteAsync(null);
        Assert.AreEqual("1.2.3", viewModel.ServiceVersion);
        Assert.AreNotEqual("\u2014", viewModel.ServiceStarted);

        await viewModel.RefreshCommand.ExecuteAsync(null);

        Assert.AreEqual("\u2014", viewModel.ServiceVersion);
        Assert.AreEqual("\u2014", viewModel.ServiceStarted);
        Assert.AreEqual("Service reported a problem", viewModel.Status);
    }

    [TestMethod]
    public async Task StartCommandDisplaysCompleteEvidenceTimeline()
    {
        string? observedFailureStage = "not-called";
        var completedRun = CreateSuccessfulRun();
        var viewModel = new MainWindowViewModel(
            static _ =>
                Task.FromResult(
                    IpcResponse.Succeeded(
                        Guid.NewGuid(),
                        new HealthSnapshot(
                            "healthy",
                            "test",
                            runStart,
                            runStart))),
            _ =>
                Task.FromResult(
                    IpcResponse.Succeeded(Guid.NewGuid(), completedRun)),
            (idempotencyKey, failureStage, cancellationToken) =>
            {
                Assert.AreNotEqual(Guid.Empty, idempotencyKey);
                Assert.IsFalse(cancellationToken.IsCancellationRequested);
                observedFailureStage = failureStage;
                return Task.FromResult(
                    IpcResponse.Succeeded(Guid.NewGuid(), completedRun));
            });

        await viewModel.StartSimulationCommand.ExecuteAsync(null);

        Assert.IsNull(observedFailureStage);
        Assert.AreEqual("Succeeded", viewModel.SimulationStatus);
        Assert.AreEqual(
            completedRun.RunId.ToString("D"),
            viewModel.SimulationRunId);
        Assert.HasCount(8, viewModel.SimulationTimeline);
        Assert.AreEqual(
            "Verification",
            viewModel.SimulationTimeline[6].Stage);
        Assert.AreEqual(
            "Cleanup",
            viewModel.SimulationTimeline[7].Stage);
    }

    [TestMethod]
    public async Task StartAuthorizationFailureIsDisplayedWithoutAFalseRun()
    {
        var viewModel = new MainWindowViewModel(
            static _ => throw new AssertFailedException("Health was not requested."),
            static _ => throw new AssertFailedException("Latest was not requested."),
            static (idempotencyKey, failureStage, cancellationToken) =>
            {
                _ = idempotencyKey;
                _ = failureStage;
                _ = cancellationToken;
                return Task.FromResult(
                    IpcResponse.Failed(
                        Guid.NewGuid(),
                        "simulation_start_forbidden",
                        "An elevated operator is required."));
            });

        await viewModel.StartSimulationCommand.ExecuteAsync(null);

        Assert.AreEqual(
            "Simulation not accepted",
            viewModel.SimulationStatus);
        StringAssert.Contains(
            viewModel.SimulationSummary,
            "elevated operator");
        Assert.IsEmpty(viewModel.SimulationTimeline);
    }

    [TestMethod]
    public async Task AmbiguousStartFailureReusesTheSameIdempotencyKey()
    {
        var observedKeys = new List<Guid>();
        var completedRun = CreateSuccessfulRun();
        var attempt = 0;
        var viewModel = new MainWindowViewModel(
            static _ => throw new AssertFailedException("Health was not requested."),
            static _ => throw new AssertFailedException("Latest was not requested."),
            (idempotencyKey, failureStage, cancellationToken) =>
            {
                _ = failureStage;
                _ = cancellationToken;
                observedKeys.Add(idempotencyKey);
                attempt++;
                return attempt == 1
                    ? Task.FromException<IpcResponse>(
                        new TimeoutException("The response was ambiguous."))
                    : Task.FromResult(
                        IpcResponse.Succeeded(Guid.NewGuid(), completedRun));
            });

        await viewModel.StartSimulationCommand.ExecuteAsync(null);
        StringAssert.Contains(
            viewModel.SimulationSummary,
            "reuse the same simulation request identity");

        await viewModel.StartSimulationCommand.ExecuteAsync(null);

        Assert.HasCount(2, observedKeys);
        Assert.AreEqual(observedKeys[0], observedKeys[1]);
        Assert.AreEqual("Succeeded", viewModel.SimulationStatus);
    }

    [TestMethod]
    public async Task PollingDoesNotAttributeAnotherCallersLatestRun()
    {
        var acceptedRun = CreateQueuedRun(
            Guid.Parse("d4e32bcf-93d4-4497-9b24-8d357a7657a1"));
        var otherRun = CreateRunningRun(
            Guid.Parse("dc900e17-a3a8-4aa3-9e62-bc8d9dd9db67"));
        var viewModel = new MainWindowViewModel(
            static _ => throw new AssertFailedException("Health was not requested."),
            _ => Task.FromResult(
                IpcResponse.Succeeded(Guid.NewGuid(), otherRun)),
            (_, _, _) => Task.FromResult(
                IpcResponse.Succeeded(Guid.NewGuid(), acceptedRun)));

        await viewModel.StartSimulationCommand.ExecuteAsync(null);

        Assert.AreEqual(
            acceptedRun.RunId.ToString("D"),
            viewModel.SimulationRunId);
        Assert.AreEqual(
            "A newer run is now active",
            viewModel.SimulationStatus);
        StringAssert.Contains(
            viewModel.SimulationSummary,
            "will not attribute");
        Assert.IsEmpty(viewModel.SimulationTimeline);
    }

    private static SimulationRunSnapshot CreateSuccessfulRun()
    {
        var evidence = SimulationContractValues.Stages
            .Select(
                static (stage, index) =>
                    new SimulationEvidenceSnapshot(
                        index + 1,
                        stage,
                        SimulationContractValues.SucceededOutcome,
                        runStart.AddSeconds(index),
                        "simulation.stage_succeeded",
                        $"The simulated {stage} stage completed."))
            .ToArray();
        return new SimulationRunSnapshot(
            Guid.Parse("0f57f13d-93b4-4915-a47f-fc4314508fc4"),
            SimulationContractValues.SucceededStatus,
            null,
            SimulationContractValues.CleanupStage,
            SimulationContractValues.SucceededOutcome,
            runStart,
            runStart,
            runStart.AddSeconds(evidence.Length),
            Array.AsReadOnly(evidence));
    }

    private static SimulationRunSnapshot CreateQueuedRun(Guid runId) =>
        new(
            runId,
            SimulationContractValues.QueuedStatus,
            null,
            null,
            null,
            runStart,
            null,
            null,
            Array.Empty<SimulationEvidenceSnapshot>());

    private static SimulationRunSnapshot CreateRunningRun(Guid runId) =>
        new(
            runId,
            SimulationContractValues.RunningStatus,
            SimulationContractValues.PreflightStage,
            null,
            null,
            runStart,
            runStart,
            null,
            Array.Empty<SimulationEvidenceSnapshot>());
}
