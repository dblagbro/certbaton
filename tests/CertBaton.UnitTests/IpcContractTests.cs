using CertBaton.Contracts;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class IpcContractTests
{
    private static readonly DateTimeOffset requestedAtUtc =
        new(2026, 7, 29, 12, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void RequestFactoriesCreateMethodSpecificPayloads()
    {
        var idempotencyKey = Guid.NewGuid();

        var health = IpcRequest.CreateHealth(TimeProvider.System);
        var latest = IpcRequest.CreateSimulationLatest(TimeProvider.System);
        var start = IpcRequest.CreateSimulationStart(
            TimeProvider.System,
            idempotencyKey,
            SimulationContractValues.ChallengeStage);

        Assert.AreEqual(IpcProtocol.HealthMethod, health.Method);
        Assert.IsNull(health.Payload);
        Assert.AreEqual(IpcProtocol.SimulationLatestMethod, latest.Method);
        Assert.IsNull(latest.Payload);
        Assert.AreEqual(IpcProtocol.SimulationStartMethod, start.Method);
        Assert.AreEqual(idempotencyKey, start.Payload?.IdempotencyKey);
        Assert.AreEqual(
            SimulationContractValues.ChallengeStage,
            start.Payload?.FailureStage);
        Assert.IsTrue(health.TryValidateMethodPayload(out _));
        Assert.IsTrue(latest.TryValidateMethodPayload(out _));
        Assert.IsTrue(start.TryValidateMethodPayload(out _));
    }

    [TestMethod]
    public void SimulationStartPayloadRejectsEmptyKeyAndNonCanonicalStage()
    {
        var emptyKey = new SimulationStartPayload(Guid.Empty);
        var upperCaseStage = new SimulationStartPayload(
            Guid.NewGuid(),
            "Preflight");

        Assert.IsFalse(emptyKey.TryValidate(out _));
        Assert.IsFalse(upperCaseStage.TryValidate(out _));
        Assert.AreEqual(8, SimulationContractValues.Stages.Count);
    }

    [TestMethod]
    public void HealthAndLatestRejectStartPayload()
    {
        var now = DateTimeOffset.UtcNow;
        var payload = new SimulationStartPayload(Guid.NewGuid());
        var health = new IpcRequest(
            IpcProtocol.CurrentVersion,
            Guid.NewGuid(),
            IpcProtocol.HealthMethod,
            now,
            now.AddSeconds(3),
            payload);
        var latest = health with
        {
            Method = IpcProtocol.SimulationLatestMethod,
        };

        Assert.IsFalse(health.TryValidateMethodPayload(out _));
        Assert.IsFalse(latest.TryValidateMethodPayload(out _));
    }

    [TestMethod]
    public void InterruptedSnapshotAllowsMissingTerminalStage()
    {
        var snapshot = new SimulationRunSnapshot(
            Guid.NewGuid(),
            SimulationContractValues.InterruptedStatus,
            null,
            null,
            SimulationContractValues.InterruptedOutcome,
            requestedAtUtc,
            requestedAtUtc.AddSeconds(1),
            requestedAtUtc.AddSeconds(2),
            []);

        Assert.IsTrue(snapshot.TryValidate(out var error), error);
    }

    [TestMethod]
    public void SucceededSnapshotRequiresAllEightSuccessfulStagesInOrder()
    {
        var incomplete = CreateSucceededSnapshot(
            SimulationContractValues.Stages
                .Take(SimulationContractValues.Stages.Count - 1));
        var complete = CreateSucceededSnapshot(SimulationContractValues.Stages);

        Assert.IsFalse(incomplete.TryValidate(out _));
        Assert.IsTrue(complete.TryValidate(out var error), error);
    }

    [TestMethod]
    public void SnapshotRejectsEvidenceOverContractBound()
    {
        var evidence = Enumerable
            .Range(1, SimulationContractValues.MaximumEvidenceRecords + 1)
            .Select(
                sequence =>
                    new SimulationEvidenceSnapshot(
                        sequence,
                        null,
                        null,
                        requestedAtUtc.AddSeconds(1),
                        "simulation.note",
                        "Bounded test evidence."))
            .ToArray();
        var snapshot = new SimulationRunSnapshot(
            Guid.NewGuid(),
            SimulationContractValues.RunningStatus,
            SimulationContractValues.PreflightStage,
            null,
            null,
            requestedAtUtc,
            requestedAtUtc.AddSeconds(1),
            null,
            evidence);

        Assert.IsFalse(snapshot.TryValidate(out _));
    }

    [TestMethod]
    public void SuccessfulEnvelopeRequiresExactlyOneMethodSpecificPayload()
    {
        var responseWithNoPayload = new IpcResponse(
            IpcProtocol.CurrentVersion,
            Guid.NewGuid(),
            true,
            new IpcResultEnvelope(null, null),
            null);
        var responseWithBothPayloads = responseWithNoPayload with
        {
            Result = new IpcResultEnvelope(
                new HealthSnapshot(
                    "healthy",
                    "test",
                    requestedAtUtc,
                    requestedAtUtc),
                CreateSucceededSnapshot(SimulationContractValues.Stages)),
        };

        Assert.IsFalse(
            responseWithNoPayload.TryValidateForMethod(
                IpcProtocol.HealthMethod,
                out _));
        Assert.IsFalse(
            responseWithBothPayloads.TryValidateForMethod(
                IpcProtocol.HealthMethod,
                out _));
    }

    private static SimulationRunSnapshot CreateSucceededSnapshot(
        IEnumerable<string> stages)
    {
        var evidence = stages
            .Select(
                (stage, index) =>
                    new SimulationEvidenceSnapshot(
                        index + 1,
                        stage,
                        SimulationContractValues.SucceededOutcome,
                        requestedAtUtc.AddSeconds(index + 1),
                        "simulation.stage_succeeded",
                        "The simulated stage succeeded."))
            .ToArray();

        return new SimulationRunSnapshot(
            Guid.NewGuid(),
            SimulationContractValues.SucceededStatus,
            null,
            SimulationContractValues.CleanupStage,
            SimulationContractValues.SucceededOutcome,
            requestedAtUtc,
            requestedAtUtc,
            requestedAtUtc.AddSeconds(10),
            evidence);
    }
}
