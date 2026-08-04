using System.Globalization;
using System.Threading.Channels;
using CertBaton.Application.Simulation;
using CertBaton.Application.Simulation.Persistence;
using CertBaton.Domain.Renewals;

namespace CertBaton.Service;

public interface ISimulationCoordinator
{
    SimulationJobDetails? Latest { get; }

    Task<SimulationJobDetails> StartAsync(
        Guid idempotencyKey,
        RenewalStage? failureStage,
        CancellationToken cancellationToken);
}

public sealed class SimulationAlreadyActiveException : InvalidOperationException
{
    public SimulationAlreadyActiveException()
        : base("A simulated renewal is already queued or running.")
    {
    }
}

public sealed partial class SimulationCoordinator : BackgroundService, ISimulationCoordinator
{
    private const int CommandCapacity = 16;
    private readonly ISimulationJobStore store;
    private readonly SimulatedRenewalRunner runner;
    private readonly TimeProvider timeProvider;
    private readonly ILogger<SimulationCoordinator> logger;
    private readonly LiveMaintenanceGate maintenanceGate;
    private readonly Channel<StartSimulationCommand> commands =
        Channel.CreateBounded<StartSimulationCommand>(
            new BoundedChannelOptions(CommandCapacity)
            {
                AllowSynchronousContinuations = false,
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false,
            });
    private readonly Guid executionEpoch = Guid.CreateVersion7();
    private SimulationJobDetails? latest;

    public SimulationCoordinator(
        ISimulationJobStore store,
        SimulatedRenewalRunner runner,
        TimeProvider timeProvider,
        ILogger<SimulationCoordinator> logger,
        LiveMaintenanceGate? maintenanceGate = null)
    {
        this.store = store;
        this.runner = runner;
        this.timeProvider = timeProvider;
        this.logger = logger;
        this.maintenanceGate = maintenanceGate ?? new LiveMaintenanceGate();
    }

    public SimulationJobDetails? Latest => Volatile.Read(ref latest);

    public async Task<SimulationJobDetails> StartAsync(
        Guid idempotencyKey,
        RenewalStage? failureStage,
        CancellationToken cancellationToken)
    {
        maintenanceGate.ThrowIfPaused();
        if (idempotencyKey == Guid.Empty)
        {
            throw new ArgumentException(
                "A non-empty simulation idempotency key is required.",
                nameof(idempotencyKey));
        }

        if (failureStage.HasValue && !Enum.IsDefined(failureStage.Value))
        {
            throw new ArgumentOutOfRangeException(
                nameof(failureStage),
                failureStage,
                "The simulated failure stage is invalid.");
        }

        var command = new StartSimulationCommand(
            idempotencyKey,
            failureStage,
            cancellationToken);
        using var cancellationRegistration = cancellationToken.UnsafeRegister(
            static state =>
                ((StartSimulationCommand)state!).TryCancelBeforeClaim(),
            command);
        try
        {
            await commands.Writer
                .WriteAsync(command, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            command.TryCancelBeforeClaim();
            throw;
        }

        return await command.Completion.Task
            .ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await maintenanceGate.WaitUntilOpenAsync(stoppingToken)
                .ConfigureAwait(false);
            store.Initialize(GetUtcNow());
            Publish(store.GetLatestJobWithEvidence());

            while (!stoppingToken.IsCancellationRequested)
            {
                while (commands.Reader.TryRead(out var command))
                {
                    if (command.TryBegin())
                    {
                        HandleStartCommand(command);
                    }
                }

                var claimed = store.TryClaimNextQueuedJob(
                    executionEpoch,
                    GetUtcNow());
                if (claimed is not null)
                {
                    await ProcessClaimedJobAsync(claimed).ConfigureAwait(false);
                    continue;
                }

                if (!await commands.Reader
                        .WaitToReadAsync(stoppingToken)
                        .ConfigureAwait(false))
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            commands.Writer.TryComplete();
            while (commands.Reader.TryRead(out var command))
            {
                command.Completion.TrySetCanceled(stoppingToken);
            }
        }
    }

    private void HandleStartCommand(StartSimulationCommand command)
    {
        try
        {
            var requestKey = command.IdempotencyKey.ToString(
                "D",
                CultureInfo.InvariantCulture);
            var proposedJobId = Guid.CreateVersion7();
            SimulationJobSnapshot job;
            try
            {
                job = store.CreateOrGetJob(
                    proposedJobId,
                    requestKey,
                    command.FailureStage,
                    GetUtcNow());
            }
            catch (SimulationJobAlreadyActiveException)
            {
                throw new SimulationAlreadyActiveException();
            }

            var details = store.FindJobWithEvidence(job.JobId)
                ?? throw new InvalidOperationException(
                    "The newly created simulation job could not be read.");
            if (job.JobId == proposedJobId)
            {
                Publish(details);
            }

            command.Completion.TrySetResult(details);
        }
        catch (Exception exception)
        {
            command.Completion.TrySetException(exception);
        }
    }

    private async Task ProcessClaimedJobAsync(SimulationJobSnapshot claimed)
    {
        PublishRequired(claimed.JobId);
        var plan = claimed.FailureStage is { } failureStage
            ? new RenewalSimulationPlan(new SimulationFailure(failureStage))
            : new RenewalSimulationPlan();

        try
        {
            var result = await runner.RunAsync(
                    claimed.JobId,
                    plan,
                    evidence =>
                    {
                        store.AppendStageEvidence(
                            claimed.JobId,
                            executionEpoch,
                            evidence.Stage,
                            evidence.Outcome,
                            evidence.RecordedAtUtc,
                            evidence.Code,
                            evidence.Description);
                        PublishRequired(claimed.JobId);
                        return ValueTask.CompletedTask;
                    },
                    CancellationToken.None)
                .ConfigureAwait(false);

            var status = result.Outcome switch
            {
                RenewalTerminalOutcome.Succeeded =>
                    SimulationJobStatus.Succeeded,
                RenewalTerminalOutcome.Failed =>
                    SimulationJobStatus.Failed,
                RenewalTerminalOutcome.Cancelled =>
                    SimulationJobStatus.Cancelled,
                _ => throw new InvalidOperationException(
                    "The simulator returned an unsupported terminal outcome."),
            };
            var terminalCode = result.Outcome switch
            {
                RenewalTerminalOutcome.Succeeded => "simulation.succeeded",
                RenewalTerminalOutcome.Failed => "simulation.failed",
                RenewalTerminalOutcome.Cancelled => "simulation.cancelled",
                _ => throw new InvalidOperationException(
                    "The simulator returned an unsupported terminal outcome."),
            };

            store.CompleteJob(
                claimed.JobId,
                executionEpoch,
                status,
                result.CompletedAtUtc,
                terminalCode,
                $"The simulated renewal ended with outcome {result.Outcome}.");
            PublishRequired(claimed.JobId);
            LogSimulationCompleted(logger, claimed.JobId, status);
        }
        catch (Exception exception)
        {
            LogSimulationProcessingFailed(logger, claimed.JobId, exception);
            throw;
        }
    }

    private void PublishRequired(Guid jobId)
    {
        var details = store.FindJobWithEvidence(jobId)
            ?? throw new InvalidOperationException(
                "The active simulation job could not be read.");
        Publish(details);
    }

    private void Publish(SimulationJobDetails? details) =>
        Volatile.Write(ref latest, details);

    private DateTimeOffset GetUtcNow() =>
        timeProvider.GetUtcNow().ToUniversalTime();

    [LoggerMessage(
        EventId = 1100,
        Level = LogLevel.Information,
        Message = "Simulated renewal {JobId} completed with status {Status}.")]
    private static partial void LogSimulationCompleted(
        ILogger logger,
        Guid jobId,
        SimulationJobStatus status);

    [LoggerMessage(
        EventId = 1101,
        Level = LogLevel.Error,
        Message = "Simulated renewal {JobId} stopped because its service-owned processing failed.")]
    private static partial void LogSimulationProcessingFailed(
        ILogger logger,
        Guid jobId,
        Exception exception);

    private sealed record StartSimulationCommand(
        Guid IdempotencyKey,
        RenewalStage? FailureStage,
        CancellationToken RequestCancellationToken)
    {
        private const int Pending = 0;
        private const int Begun = 1;
        private const int Cancelled = 2;
        private int state;

        public TaskCompletionSource<SimulationJobDetails> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool TryBegin() =>
            Interlocked.CompareExchange(ref state, Begun, Pending) == Pending;

        public void TryCancelBeforeClaim()
        {
            if (Interlocked.CompareExchange(
                    ref state,
                    Cancelled,
                    Pending) == Pending)
            {
                Completion.TrySetCanceled(RequestCancellationToken);
            }
        }
    }
}
