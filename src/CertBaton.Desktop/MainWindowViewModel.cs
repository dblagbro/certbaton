using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows.Media;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CertBaton.Desktop;

public sealed class MainWindowViewModel : ObservableObject
{
    private const string UnavailableValue = "\u2014";
    private readonly Func<CancellationToken, Task<IpcResponse>> getHealthAsync;
    private readonly Func<CancellationToken, Task<IpcResponse>> getLatestSimulationAsync;
    private readonly Func<Guid, string?, CancellationToken, Task<IpcResponse>>
        startSimulationAsync;
    private string status = "Checking service…";
    private string summary = "Waiting for the local CertBaton service.";
    private string serviceVersion = UnavailableValue;
    private string serviceStarted = UnavailableValue;
    private string lastChecked = "Not checked yet";
    private Brush statusBrush = CreateBrush(181, 122, 0);
    private string simulationStatus = "No simulation yet";
    private string simulationSummary =
        "Run the local, no-network renewal simulator to inspect every handoff.";
    private string simulationRunId = UnavailableValue;
    private string simulationRequested = UnavailableValue;
    private string simulationCompleted = UnavailableValue;
    private Brush simulationStatusBrush = CreateBrush(101, 120, 138);
    private SimulationFailureChoice selectedFailure;
    private PendingSimulationRequest? pendingSimulationRequest;
    private bool isRefreshing;

    public MainWindowViewModel()
        : this(new CertBatonPipeClient())
    {
    }

    private MainWindowViewModel(CertBatonPipeClient client)
        : this(
            client.GetHealthAsync,
            client.GetLatestSimulationAsync,
            client.StartSimulationAsync)
    {
    }

    internal MainWindowViewModel(
        Func<CancellationToken, Task<IpcResponse>> getHealthAsync)
        : this(
            getHealthAsync,
            static _ =>
                Task.FromResult(
                    IpcResponse.Failed(
                        Guid.NewGuid(),
                        "simulation_not_found",
                        "No simulated renewal has been recorded yet.")),
            static (idempotencyKey, failureStage, cancellationToken) =>
            {
                _ = idempotencyKey;
                _ = failureStage;
                _ = cancellationToken;
                return Task.FromResult(
                    IpcResponse.Failed(
                        Guid.NewGuid(),
                        "simulation_start_unavailable",
                        "Simulation start is unavailable in this test."));
            })
    {
    }

    internal MainWindowViewModel(
        Func<CancellationToken, Task<IpcResponse>> getHealthAsync,
        Func<CancellationToken, Task<IpcResponse>> getLatestSimulationAsync,
        Func<Guid, string?, CancellationToken, Task<IpcResponse>>
            startSimulationAsync)
    {
        this.getHealthAsync = getHealthAsync;
        this.getLatestSimulationAsync = getLatestSimulationAsync;
        this.startSimulationAsync = startSimulationAsync;

        FailureChoices = Array.AsReadOnly(
        [
            new SimulationFailureChoice("No injected failure", null),
            new SimulationFailureChoice("Fail at preflight", "preflight"),
            new SimulationFailureChoice("Fail at ACME order", "order"),
            new SimulationFailureChoice("Fail at challenge", "challenge"),
            new SimulationFailureChoice("Fail at issuance", "issuance"),
            new SimulationFailureChoice("Fail at deployment", "deployment"),
            new SimulationFailureChoice("Fail at activation", "activation"),
            new SimulationFailureChoice("Fail at verification", "verification"),
            new SimulationFailureChoice("Fail at cleanup", "cleanup"),
        ]);
        selectedFailure = FailureChoices[0];
        RefreshCommand = new AsyncRelayCommand(RefreshAsync, () => !IsRefreshing);
        StartSimulationCommand =
            new AsyncRelayCommand(StartSimulationAsync, () => !IsRefreshing);
    }

    public IAsyncRelayCommand RefreshCommand { get; }

    public IAsyncRelayCommand StartSimulationCommand { get; }

    public IReadOnlyList<SimulationFailureChoice> FailureChoices { get; }

    public ObservableCollection<SimulationTimelineItem> SimulationTimeline { get; } = [];

    public string Status
    {
        get => status;
        private set => SetProperty(ref status, value);
    }

    public string Summary
    {
        get => summary;
        private set => SetProperty(ref summary, value);
    }

    public string ServiceVersion
    {
        get => serviceVersion;
        private set => SetProperty(ref serviceVersion, value);
    }

    public string ServiceStarted
    {
        get => serviceStarted;
        private set => SetProperty(ref serviceStarted, value);
    }

    public string LastChecked
    {
        get => lastChecked;
        private set => SetProperty(ref lastChecked, value);
    }

    public Brush StatusBrush
    {
        get => statusBrush;
        private set => SetProperty(ref statusBrush, value);
    }

    public string SimulationStatus
    {
        get => simulationStatus;
        private set => SetProperty(ref simulationStatus, value);
    }

    public string SimulationSummary
    {
        get => simulationSummary;
        private set => SetProperty(ref simulationSummary, value);
    }

    public string SimulationRunId
    {
        get => simulationRunId;
        private set => SetProperty(ref simulationRunId, value);
    }

    public string SimulationRequested
    {
        get => simulationRequested;
        private set => SetProperty(ref simulationRequested, value);
    }

    public string SimulationCompleted
    {
        get => simulationCompleted;
        private set => SetProperty(ref simulationCompleted, value);
    }

    public Brush SimulationStatusBrush
    {
        get => simulationStatusBrush;
        private set => SetProperty(ref simulationStatusBrush, value);
    }

    public SimulationFailureChoice SelectedFailure
    {
        get => selectedFailure;
        set => SetProperty(ref selectedFailure, value);
    }

    public bool IsRefreshing
    {
        get => isRefreshing;
        private set
        {
            if (SetProperty(ref isRefreshing, value))
            {
                RefreshCommand.NotifyCanExecuteChanged();
                StartSimulationCommand.NotifyCanExecuteChanged();
            }
        }
    }

    private async Task RefreshAsync()
    {
        SetBusyState("Checking service…", "Opening the authenticated local service channel.");

        try
        {
            var response = await getHealthAsync(CancellationToken.None)
                .ConfigureAwait(true);
            var health = response.Result?.Health;
            if (!response.Success || health is null)
            {
                Status = "Service reported a problem";
                Summary = response.Error?.Message ?? "No diagnostic details were returned.";
                ClearServiceDetails();
                StatusBrush = CreateBrush(184, 50, 50);
                return;
            }

            Status = "Service is healthy";
            Summary =
                "The Windows client is using the authenticated local service channel.";
            ServiceVersion = health.ServiceVersion;
            ServiceStarted = FormatLocal(health.StartedAtUtc);
            StatusBrush = CreateBrush(33, 132, 88);

            var simulationResponse = await getLatestSimulationAsync(
                    CancellationToken.None)
                .ConfigureAwait(true);
            ApplySimulationResponse(simulationResponse);
        }
        catch (Exception exception) when (IsExpectedClientException(exception))
        {
            Status = "Service is unavailable";
            Summary = exception.Message;
            ClearServiceDetails();
            StatusBrush = CreateBrush(184, 50, 50);
        }
        finally
        {
            FinishBusyState();
        }
    }

    private async Task StartSimulationAsync()
    {
        IsRefreshing = true;
        SimulationStatus = "Queueing simulation…";
        SimulationSummary =
            "The request is being handed to the service-owned durable worker.";
        SimulationStatusBrush = CreateBrush(181, 122, 0);

        try
        {
            var pendingRequest = pendingSimulationRequest ??
                new PendingSimulationRequest(
                    Guid.CreateVersion7(),
                    SelectedFailure.Stage);
            pendingSimulationRequest = pendingRequest;
            var response = await startSimulationAsync(
                    pendingRequest.IdempotencyKey,
                    pendingRequest.FailureStage,
                    CancellationToken.None)
                .ConfigureAwait(true);
            if (!response.Success)
            {
                if (IsDefinitiveStartRejection(response.Error?.Code))
                {
                    pendingSimulationRequest = null;
                }

                _ = ApplySimulationResponse(response);
                return;
            }

            if (!ApplySimulationResponse(response))
            {
                return;
            }

            var acceptedRunId = response.Result!.SimulationRun!.RunId;
            pendingSimulationRequest = null;
            for (var attempt = 0; attempt < 5; attempt++)
            {
                var run = response.Result?.SimulationRun;
                if (run?.Status is not
                    SimulationContractValues.QueuedStatus and not
                    SimulationContractValues.RunningStatus)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(150))
                    .ConfigureAwait(true);
                response = await getLatestSimulationAsync(CancellationToken.None)
                    .ConfigureAwait(true);
                var observedRun = response.Result?.SimulationRun;
                if (response.Success &&
                    observedRun is not null &&
                    observedRun.RunId != acceptedRunId)
                {
                    SimulationStatus = "A newer run is now active";
                    SimulationSummary =
                        $"The service now reports run {observedRun.RunId:D} as latest. This window will not attribute that run's evidence to accepted run {acceptedRunId:D}.";
                    SimulationStatusBrush = CreateBrush(181, 122, 0);
                    break;
                }

                if (!ApplySimulationResponse(response))
                {
                    break;
                }
            }
        }
        catch (Exception exception) when (IsExpectedClientException(exception))
        {
            SimulationStatus = "Simulation unavailable";
            SimulationSummary = pendingSimulationRequest is null
                ? exception.Message
                : $"{exception.Message} A retry will reuse the same simulation request identity.";
            SimulationStatusBrush = CreateBrush(184, 50, 50);
        }
        finally
        {
            FinishBusyState();
        }
    }

    private bool ApplySimulationResponse(IpcResponse response)
    {
        if (!response.Success)
        {
            if (string.Equals(
                    response.Error?.Code,
                    "simulation_not_found",
                    StringComparison.Ordinal))
            {
                ClearSimulation();
                return true;
            }

            SimulationStatus = "Simulation not accepted";
            SimulationSummary =
                response.Error?.Message ?? "No simulation diagnostic was returned.";
            SimulationStatusBrush = CreateBrush(184, 50, 50);
            return false;
        }

        var run = response.Result?.SimulationRun;
        string? validationError = null;
        if (run is null || !run.TryValidate(out validationError))
        {
            SimulationStatus = "Simulation data is invalid";
            SimulationSummary =
                validationError ?? "The service returned no simulation data.";
            SimulationStatusBrush = CreateBrush(184, 50, 50);
            return false;
        }

        SimulationStatus = ToDisplayValue(run.Status);
        SimulationSummary = BuildRunSummary(run);
        SimulationRunId = run.RunId.ToString("D", CultureInfo.InvariantCulture);
        SimulationRequested = FormatLocal(run.RequestedAtUtc);
        SimulationCompleted = run.CompletedAtUtc.HasValue
            ? FormatLocal(run.CompletedAtUtc.Value)
            : UnavailableValue;
        SimulationStatusBrush = run.Status switch
        {
            SimulationContractValues.SucceededStatus => CreateBrush(33, 132, 88),
            SimulationContractValues.FailedStatus or
            SimulationContractValues.InterruptedStatus => CreateBrush(184, 50, 50),
            _ => CreateBrush(181, 122, 0),
        };

        SimulationTimeline.Clear();
        foreach (var item in run.Evidence)
        {
            SimulationTimeline.Add(
                new SimulationTimelineItem(
                    item.Sequence,
                    item.Stage is null ? "Run" : ToDisplayValue(item.Stage),
                    item.Outcome is null ? "Recorded" : ToDisplayValue(item.Outcome),
                    FormatLocal(item.RecordedAtUtc),
                    item.Description,
                    item.Code));
        }

        return true;
    }

    private static string BuildRunSummary(SimulationRunSnapshot run) =>
        run.Status switch
        {
            SimulationContractValues.QueuedStatus =>
                "The durable job is queued and no stage has started.",
            SimulationContractValues.RunningStatus =>
                $"The service owns the run and is processing {ToDisplayValue(run.CurrentStage ?? "the next stage")}.",
            SimulationContractValues.SucceededStatus =>
                "All eight synthetic stages completed, including independent verification and cleanup.",
            SimulationContractValues.FailedStatus =>
                $"The injected failure stopped the run at {ToDisplayValue(run.TerminalStage ?? "an unknown stage")}.",
            SimulationContractValues.CancelledStatus =>
                "The simulator stopped at a safe stage boundary.",
            SimulationContractValues.InterruptedStatus =>
                "Startup recovery found work without a durable terminal result; it was not reported as success.",
            _ => "The simulation state is not recognized.",
        };

    private static bool IsExpectedClientException(Exception exception) =>
        exception is
            IOException or
            TimeoutException or
            UnauthorizedAccessException or
            IpcProtocolException;

    private static bool IsDefinitiveStartRejection(string? code) =>
        code is
            "invalid_request" or
            "protocol_version_unsupported" or
            "invalid_deadline" or
            "method_not_found" or
            "simulation_start_forbidden" or
            "simulation_already_active" or
            "simulation_idempotency_conflict";

    private void SetBusyState(string newStatus, string newSummary)
    {
        IsRefreshing = true;
        Status = newStatus;
        Summary = newSummary;
        StatusBrush = CreateBrush(181, 122, 0);
    }

    private void FinishBusyState()
    {
        LastChecked = DateTimeOffset.Now.ToString("T", CultureInfo.CurrentCulture);
        IsRefreshing = false;
    }

    private void ClearServiceDetails()
    {
        ServiceVersion = UnavailableValue;
        ServiceStarted = UnavailableValue;
    }

    private void ClearSimulation()
    {
        SimulationStatus = "No simulation yet";
        SimulationSummary =
            "Run the local, no-network renewal simulator to inspect every handoff.";
        SimulationRunId = UnavailableValue;
        SimulationRequested = UnavailableValue;
        SimulationCompleted = UnavailableValue;
        SimulationStatusBrush = CreateBrush(101, 120, 138);
        SimulationTimeline.Clear();
    }

    private static string FormatLocal(DateTimeOffset value) =>
        value.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);

    private static string ToDisplayValue(string value) =>
        CultureInfo.CurrentCulture.TextInfo.ToTitleCase(
            value.Replace('-', ' ').Replace('_', ' '));

    private static SolidColorBrush CreateBrush(byte red, byte green, byte blue) =>
        new SolidColorBrush(Color.FromRgb(red, green, blue));

    private sealed record PendingSimulationRequest(
        Guid IdempotencyKey,
        string? FailureStage);
}

public sealed record SimulationFailureChoice(string Label, string? Stage);

public sealed record SimulationTimelineItem(
    long Sequence,
    string Stage,
    string Outcome,
    string RecordedAt,
    string Description,
    string Code);
