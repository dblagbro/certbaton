using System.IO;
using System.Text.Json;
using CertBaton.Contracts;
using CertBaton.Ctl;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class CtlCommandLineTests
{
    [TestMethod]
    public async Task UnknownSwitchReturnsUsageErrorWithoutContactingService()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var serviceContacted = false;

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            ["health", "--unknown"],
            output,
            error,
            () =>
            {
                serviceContacted = true;
                throw new InvalidOperationException("The parser should reject the option first.");
            });

        Assert.AreEqual(2, exitCode);
        Assert.IsFalse(serviceContacted);
        Assert.AreEqual(string.Empty, output.ToString());
        StringAssert.Contains(error.ToString(), "Unknown option: --unknown");
        StringAssert.Contains(error.ToString(), "Usage:");
    }

    [TestMethod]
    public async Task UnknownSwitchIsRejectedEvenWhenHelpIsRequested()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            ["--help", "--unknown"],
            output,
            error);

        Assert.AreEqual(2, exitCode);
        Assert.AreEqual(string.Empty, output.ToString());
        StringAssert.Contains(error.ToString(), "Unknown option: --unknown");
    }

    [TestMethod]
    public async Task SimulationLatestWritesTheRunAsJson()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var run = CreateQueuedRun();
        var latestContacted = false;

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            ["simulation", "latest", "--json"],
            output,
            error,
            getLatestSimulationAsync: () =>
            {
                latestContacted = true;
                return Task.FromResult(IpcResponse.Succeeded(Guid.NewGuid(), run));
            });

        Assert.AreEqual(0, exitCode);
        Assert.IsTrue(latestContacted);
        Assert.AreEqual(string.Empty, error.ToString());

        using var document = JsonDocument.Parse(output.ToString());
        Assert.AreEqual(
            run.RunId,
            document.RootElement.GetProperty("runId").GetGuid());
        Assert.AreEqual(
            SimulationContractValues.QueuedStatus,
            document.RootElement.GetProperty("status").GetString());
    }

    [TestMethod]
    public async Task SimulationStartGeneratesIdempotencyKeyAndForwardsFailureStage()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var run = CreateQueuedRun();
        var observedIdempotencyKey = Guid.Empty;
        string? observedFailureStage = null;

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            [
                "simulation",
                "start",
                "--fail-stage",
                SimulationContractValues.DeploymentStage,
                "--json",
            ],
            output,
            error,
            startSimulationAsync: (idempotencyKey, failureStage) =>
            {
                observedIdempotencyKey = idempotencyKey;
                observedFailureStage = failureStage;
                return Task.FromResult(IpcResponse.Succeeded(Guid.NewGuid(), run));
            });

        Assert.AreEqual(0, exitCode);
        Assert.AreNotEqual(Guid.Empty, observedIdempotencyKey);
        Assert.AreEqual(
            SimulationContractValues.DeploymentStage,
            observedFailureStage);
        Assert.AreEqual(string.Empty, error.ToString());

        using var document = JsonDocument.Parse(output.ToString());
        Assert.AreEqual(
            run.RunId,
            document.RootElement.GetProperty("runId").GetGuid());
    }

    [TestMethod]
    public async Task SimulationStartWithoutFailureStageForwardsNull()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        string? observedFailureStage = "not-called";

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            ["simulation", "start"],
            output,
            error,
            startSimulationAsync: (_, failureStage) =>
            {
                observedFailureStage = failureStage;
                return Task.FromResult(
                    IpcResponse.Succeeded(Guid.NewGuid(), CreateQueuedRun()));
            });

        Assert.AreEqual(0, exitCode);
        Assert.IsNull(observedFailureStage);
        StringAssert.Contains(output.ToString(), "Simulation run:");
        StringAssert.Contains(output.ToString(), "Status: queued");
        Assert.AreEqual(string.Empty, error.ToString());
    }

    [TestMethod]
    public async Task ExplicitIdempotencyKeyCanBeReusedAfterAmbiguousFailure()
    {
        using var firstOutput = new StringWriter();
        using var firstError = new StringWriter();
        using var retryOutput = new StringWriter();
        using var retryError = new StringWriter();
        var expectedKey =
            Guid.Parse("019c0ad8-e632-7aea-916e-e5886c295d2a");
        var observedKeys = new List<Guid>();

        var firstExitCode = await CertBaton.Ctl.Program.RunAsync(
            [
                "simulation",
                "start",
                "--idempotency-key",
                expectedKey.ToString("D"),
            ],
            firstOutput,
            firstError,
            startSimulationAsync: (idempotencyKey, _) =>
            {
                observedKeys.Add(idempotencyKey);
                throw new TimeoutException(
                    "The service response was ambiguous.");
            });
        var retryExitCode = await CertBaton.Ctl.Program.RunAsync(
            [
                "simulation",
                "start",
                "--idempotency-key",
                expectedKey.ToString("D"),
            ],
            retryOutput,
            retryError,
            startSimulationAsync: (idempotencyKey, _) =>
            {
                observedKeys.Add(idempotencyKey);
                return Task.FromResult(
                    IpcResponse.Succeeded(
                        Guid.NewGuid(),
                        CreateQueuedRun()));
            });

        Assert.AreEqual(3, firstExitCode);
        Assert.AreEqual(0, retryExitCode);
        CollectionAssert.AreEqual(
            new[] { expectedKey, expectedKey },
            observedKeys);
        StringAssert.Contains(
            firstError.ToString(),
            "Unable to reach the CertBaton service");
        Assert.AreEqual(string.Empty, retryError.ToString());
    }

    [TestMethod]
    public async Task InvalidIdempotencyKeyIsRejectedWithoutContactingService()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var serviceContacted = false;

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            [
                "simulation",
                "start",
                "--idempotency-key",
                Guid.Empty.ToString("D"),
            ],
            output,
            error,
            startSimulationAsync: (_, _) =>
            {
                serviceContacted = true;
                throw new InvalidOperationException(
                    "The parser should reject the key first.");
            });

        Assert.AreEqual(2, exitCode);
        Assert.IsFalse(serviceContacted);
        Assert.AreEqual(string.Empty, output.ToString());
        StringAssert.Contains(
            error.ToString(),
            "--idempotency-key requires a non-empty GUID");
    }

    [TestMethod]
    public async Task UnknownFailureStageReturnsUsageErrorWithoutContactingService()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var serviceContacted = false;

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            ["simulation", "start", "--fail-stage", "Deployment"],
            output,
            error,
            startSimulationAsync: (_, _) =>
            {
                serviceContacted = true;
                throw new InvalidOperationException(
                    "The parser should reject the stage first.");
            });

        Assert.AreEqual(2, exitCode);
        Assert.IsFalse(serviceContacted);
        Assert.AreEqual(string.Empty, output.ToString());
        StringAssert.Contains(error.ToString(), "Unknown contract stage: Deployment");
        StringAssert.Contains(
            error.ToString(),
            SimulationContractValues.DeploymentStage);
    }

    [TestMethod]
    public async Task FailureStageIsRejectedForSimulationLatest()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var serviceContacted = false;

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            [
                "simulation",
                "latest",
                "--fail-stage",
                SimulationContractValues.PreflightStage,
            ],
            output,
            error,
            getLatestSimulationAsync: () =>
            {
                serviceContacted = true;
                throw new InvalidOperationException(
                    "The parser should reject the option first.");
            });

        Assert.AreEqual(2, exitCode);
        Assert.IsFalse(serviceContacted);
        Assert.AreEqual(string.Empty, output.ToString());
        StringAssert.Contains(
            error.ToString(),
            "--fail-stage is only valid with 'simulation start'");
    }

    [TestMethod]
    public async Task IdempotencyKeyIsRejectedForHealth()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var serviceContacted = false;

        var exitCode = await CertBaton.Ctl.Program.RunAsync(
            [
                "health",
                "--idempotency-key",
                "019c0ad8-e632-7aea-916e-e5886c295d2a",
            ],
            output,
            error,
            getHealthAsync: () =>
            {
                serviceContacted = true;
                throw new InvalidOperationException(
                    "The parser should reject the option first.");
            });

        Assert.AreEqual(2, exitCode);
        Assert.IsFalse(serviceContacted);
        Assert.AreEqual(string.Empty, output.ToString());
        StringAssert.Contains(
            error.ToString(),
            "--idempotency-key is only valid with 'simulation start'");
    }

    private static SimulationRunSnapshot CreateQueuedRun() =>
        new(
            Guid.Parse("019c0ad8-e632-70bd-b6f1-f84f07672665"),
            SimulationContractValues.QueuedStatus,
            null,
            null,
            null,
            new DateTimeOffset(2026, 7, 31, 12, 0, 0, TimeSpan.Zero),
            null,
            null,
            Array.Empty<SimulationEvidenceSnapshot>());
}
