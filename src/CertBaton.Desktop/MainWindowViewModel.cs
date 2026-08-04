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
    private const int RenewalPollAttempts = 8;
    private static readonly TimeSpan renewalPollInterval =
        TimeSpan.FromMilliseconds(500);
    private readonly Func<CancellationToken, Task<IpcResponse>> getHealthAsync;
    private readonly Func<CancellationToken, Task<IpcResponse>> listTargetsAsync;
    private readonly Func<Guid, Guid, CancellationToken, Task<IpcResponse>>
        startRenewalAsync;
    private readonly Func<Guid, CancellationToken, Task<IpcResponse>>
        getRenewalAsync;
    private readonly Func<CancellationToken, Task<IpcResponse>>
        getLatestSimulationAsync;
    private readonly Func<Guid, string?, CancellationToken, Task<IpcResponse>>
        startSimulationAsync;
    private readonly Func<TimeSpan, CancellationToken, Task> renewalPollDelayAsync;
    private readonly Dictionary<Guid, Guid> pendingRenewalKeys = [];
    private Guid? acceptedOperationId;
    private Guid? acceptedOperationTargetId;
    private string status = "Checking service...";
    private string summary = "Waiting for the local CertBaton service.";
    private string serviceVersion = UnavailableValue;
    private string serviceStarted = UnavailableValue;
    private string lastChecked = "Not checked yet";
    private Brush statusBrush = CreateBrush(181, 122, 0);
    private TargetSnapshot? selectedTarget;
    private string targetInventory = "Targets not loaded";
    private string selectedTargetSummary =
        "Refresh to load targets enrolled in the Windows service.";
    private string liveStatus = "Waiting for targets";
    private string liveSummary =
        "Refresh the service, then select an enrolled target to start a renewal.";
    private string liveTargetName = UnavailableValue;
    private string liveOperationId = UnavailableValue;
    private string liveRequested = UnavailableValue;
    private string liveUpdated = UnavailableValue;
    private string liveCompleted = UnavailableValue;
    private string liveFailureCode = UnavailableValue;
    private string liveCertificateFingerprint = UnavailableValue;
    private string livePublicTls = "Not verified";
    private string liveChallengeCleanup = "Not verified";
    private Brush liveStatusBrush = CreateBrush(101, 120, 138);
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
            client.ListTargetsAsync,
            client.StartRenewalAsync,
            client.GetRenewalAsync,
            client.GetLatestSimulationAsync,
            client.StartSimulationAsync,
            static (delay, cancellationToken) =>
                Task.Delay(delay, cancellationToken))
    {
    }

    internal MainWindowViewModel(
        Func<CancellationToken, Task<IpcResponse>> getHealthAsync)
        : this(
            getHealthAsync,
            static _ => EmptyTargetListResponse(),
            static (_, _, _) => LiveRenewalUnavailableResponse(),
            static (_, _) => LiveRenewalUnavailableResponse(),
            static _ => SimulationNotFoundResponse(),
            static (_, _, _) => SimulationUnavailableResponse(),
            static (_, _) => Task.CompletedTask)
    {
    }

    internal MainWindowViewModel(
        Func<CancellationToken, Task<IpcResponse>> getHealthAsync,
        Func<CancellationToken, Task<IpcResponse>> getLatestSimulationAsync,
        Func<Guid, string?, CancellationToken, Task<IpcResponse>>
            startSimulationAsync)
        : this(
            getHealthAsync,
            static _ => EmptyTargetListResponse(),
            static (_, _, _) => LiveRenewalUnavailableResponse(),
            static (_, _) => LiveRenewalUnavailableResponse(),
            getLatestSimulationAsync,
            startSimulationAsync,
            static (_, _) => Task.CompletedTask)
    {
    }

    internal MainWindowViewModel(
        Func<CancellationToken, Task<IpcResponse>> getHealthAsync,
        Func<CancellationToken, Task<IpcResponse>> listTargetsAsync,
        Func<Guid, Guid, CancellationToken, Task<IpcResponse>> startRenewalAsync,
        Func<Guid, CancellationToken, Task<IpcResponse>> getRenewalAsync,
        Func<CancellationToken, Task<IpcResponse>> getLatestSimulationAsync,
        Func<Guid, string?, CancellationToken, Task<IpcResponse>>
            startSimulationAsync,
        Func<TimeSpan, CancellationToken, Task> renewalPollDelayAsync)
    {
        this.getHealthAsync = getHealthAsync;
        this.listTargetsAsync = listTargetsAsync;
        this.startRenewalAsync = startRenewalAsync;
        this.getRenewalAsync = getRenewalAsync;
        this.getLatestSimulationAsync = getLatestSimulationAsync;
        this.startSimulationAsync = startSimulationAsync;
        this.renewalPollDelayAsync = renewalPollDelayAsync;

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
        StartRenewalCommand = new AsyncRelayCommand(
            StartRenewalAsync,
            CanStartRenewal);
        StartSimulationCommand =
            new AsyncRelayCommand(StartSimulationAsync, () => !IsRefreshing);
    }

    public IAsyncRelayCommand RefreshCommand { get; }

    public IAsyncRelayCommand StartRenewalCommand { get; }

    public IAsyncRelayCommand StartSimulationCommand { get; }

    public IReadOnlyList<SimulationFailureChoice> FailureChoices { get; }

    public ObservableCollection<TargetSnapshot> Targets { get; } = [];

    public ObservableCollection<RenewalTimelineItem> LiveTimeline { get; } = [];

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

    public TargetSnapshot? SelectedTarget
    {
        get => selectedTarget;
        set
        {
            if (SetProperty(ref selectedTarget, value))
            {
                SelectedTargetSummary = value is null
                    ? "No live target is selected."
                    : BuildTargetSummary(value);
                StartRenewalCommand.NotifyCanExecuteChanged();

                if (acceptedOperationId is null)
                {
                    SetReadyStateForSelection();
                }
            }
        }
    }

    public string TargetInventory
    {
        get => targetInventory;
        private set => SetProperty(ref targetInventory, value);
    }

    public string SelectedTargetSummary
    {
        get => selectedTargetSummary;
        private set => SetProperty(ref selectedTargetSummary, value);
    }

    public string LiveStatus
    {
        get => liveStatus;
        private set => SetProperty(ref liveStatus, value);
    }

    public string LiveSummary
    {
        get => liveSummary;
        private set => SetProperty(ref liveSummary, value);
    }

    public string LiveTargetName
    {
        get => liveTargetName;
        private set => SetProperty(ref liveTargetName, value);
    }

    public string LiveOperationId
    {
        get => liveOperationId;
        private set => SetProperty(ref liveOperationId, value);
    }

    public string LiveRequested
    {
        get => liveRequested;
        private set => SetProperty(ref liveRequested, value);
    }

    public string LiveUpdated
    {
        get => liveUpdated;
        private set => SetProperty(ref liveUpdated, value);
    }

    public string LiveCompleted
    {
        get => liveCompleted;
        private set => SetProperty(ref liveCompleted, value);
    }

    public string LiveFailureCode
    {
        get => liveFailureCode;
        private set => SetProperty(ref liveFailureCode, value);
    }

    public string LiveCertificateFingerprint
    {
        get => liveCertificateFingerprint;
        private set => SetProperty(ref liveCertificateFingerprint, value);
    }

    public string LivePublicTls
    {
        get => livePublicTls;
        private set => SetProperty(ref livePublicTls, value);
    }

    public string LiveChallengeCleanup
    {
        get => liveChallengeCleanup;
        private set => SetProperty(ref liveChallengeCleanup, value);
    }

    public Brush LiveStatusBrush
    {
        get => liveStatusBrush;
        private set => SetProperty(ref liveStatusBrush, value);
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
                StartRenewalCommand.NotifyCanExecuteChanged();
                StartSimulationCommand.NotifyCanExecuteChanged();
            }
        }
    }

    private static Task<IpcResponse> EmptyTargetListResponse() =>
        Task.FromResult(
            IpcResponse.Succeeded(
                Guid.NewGuid(),
                new TargetListSnapshot(Array.Empty<TargetSnapshot>())));

    private static Task<IpcResponse> LiveRenewalUnavailableResponse() =>
        Task.FromResult(
            IpcResponse.Failed(
                Guid.NewGuid(),
                "renewal_start_unavailable",
                "Live renewal is unavailable in this test."));

    private static Task<IpcResponse> SimulationNotFoundResponse() =>
        Task.FromResult(
            IpcResponse.Failed(
                Guid.NewGuid(),
                "simulation_not_found",
                "No simulated renewal has been recorded yet."));

    private static Task<IpcResponse> SimulationUnavailableResponse() =>
        Task.FromResult(
            IpcResponse.Failed(
                Guid.NewGuid(),
                "simulation_start_unavailable",
                "Simulation start is unavailable in this test."));

    private bool CanStartRenewal() =>
        !IsRefreshing && SelectedTarget?.Status == "ready";

    private async Task RefreshAsync()
    {
        SetBusyState(
            "Checking service...",
            "Opening the authenticated local service channel.");

        try
        {
            var response = await getHealthAsync(CancellationToken.None)
                .ConfigureAwait(true);
            var health = response.Result?.Health;
            if (!response.Success || health is null)
            {
                Status = "Service reported a problem";
                Summary = response.Error?.Message ??
                    "No diagnostic details were returned.";
                ClearServiceDetails();
                SetLiveUnavailable(
                    "Live client unavailable",
                    "The local service health check must pass before live targets can be used.");
                StatusBrush = CreateBrush(184, 50, 50);
                return;
            }

            Status = "Service is healthy";
            Summary =
                "The Windows client is using the authenticated local service channel.";
            ServiceVersion = health.ServiceVersion;
            ServiceStarted = FormatLocal(health.StartedAtUtc);
            StatusBrush = CreateBrush(33, 132, 88);

            await RefreshTargetsAsync().ConfigureAwait(true);
            if (acceptedOperationId.HasValue &&
                acceptedOperationTargetId.HasValue)
            {
                await RefreshAcceptedOperationAsync(
                        acceptedOperationId.Value,
                        acceptedOperationTargetId.Value)
                    .ConfigureAwait(true);
            }

            await RefreshSimulationAsync().ConfigureAwait(true);
        }
        catch (Exception exception) when (IsExpectedClientException(exception))
        {
            Status = exception is UnauthorizedAccessException
                ? "Service access requires approval"
                : "Service is unavailable";
            Summary = exception is UnauthorizedAccessException
                ? "Open CertBaton from an administrator session to use the authenticated service channel."
                : exception.Message;
            ClearServiceDetails();
            SetLiveUnavailable(
                exception is UnauthorizedAccessException
                    ? "Administrator approval required"
                    : "Live client unavailable",
                Summary);
            StatusBrush = CreateBrush(184, 50, 50);
        }
        finally
        {
            FinishBusyState();
        }
    }

    private async Task RefreshTargetsAsync()
    {
        try
        {
            var response = await listTargetsAsync(CancellationToken.None)
                .ConfigureAwait(true);
            _ = ApplyTargetListResponse(response);
        }
        catch (Exception exception) when (IsExpectedClientException(exception))
        {
            ClearTargets();
            SetLiveUnavailable(
                exception is UnauthorizedAccessException
                    ? "Administrator approval required"
                    : "Live targets unavailable",
                exception is UnauthorizedAccessException
                    ? "Run CertBaton from an elevated administrator session to read live target metadata."
                    : exception.Message);
        }
    }

    private async Task RefreshAcceptedOperationAsync(
        Guid operationId,
        Guid targetId)
    {
        try
        {
            var response = await getRenewalAsync(
                    operationId,
                    CancellationToken.None)
                .ConfigureAwait(true);
            _ = ApplyExpectedRenewalResponse(response, operationId, targetId);
        }
        catch (Exception exception) when (IsExpectedClientException(exception))
        {
            SetLiveUnavailable(
                exception is UnauthorizedAccessException
                    ? "Administrator approval required"
                    : "Accepted renewal unavailable",
                exception is UnauthorizedAccessException
                    ? "Run CertBaton from an elevated administrator session to read live renewal evidence."
                    : $"The accepted operation could not be refreshed: {exception.Message}");
        }
    }

    private async Task RefreshSimulationAsync()
    {
        try
        {
            var response = await getLatestSimulationAsync(CancellationToken.None)
                .ConfigureAwait(true);
            _ = ApplySimulationResponse(response);
        }
        catch (Exception exception) when (IsExpectedClientException(exception))
        {
            SimulationStatus = "Diagnostics unavailable";
            SimulationSummary = exception.Message;
            SimulationStatusBrush = CreateBrush(184, 50, 50);
        }
    }

    private bool ApplyTargetListResponse(IpcResponse response)
    {
        if (!response.Success)
        {
            ClearTargets();
            if (string.Equals(
                    response.Error?.Code,
                    "target_list_forbidden",
                    StringComparison.Ordinal))
            {
                SetLiveUnavailable(
                    "Administrator approval required",
                    "Run CertBaton from an elevated administrator session to read live target metadata.");
            }
            else
            {
                SetLiveUnavailable(
                    "Live targets unavailable",
                    response.Error?.Message ??
                        "The service returned no target inventory.");
            }

            return false;
        }

        var targetList = response.Result?.TargetList;
        string? validationError = null;
        if (targetList is null || !targetList.TryValidate(out validationError))
        {
            ClearTargets();
            SetLiveUnavailable(
                "Target data is invalid",
                validationError ?? "The service returned no target inventory.");
            return false;
        }

        var selectedTargetId = SelectedTarget?.TargetId;
        Targets.Clear();
        foreach (var target in targetList.Targets.OrderBy(
                     static item => item.DisplayName,
                     StringComparer.CurrentCultureIgnoreCase))
        {
            Targets.Add(target);
        }

        TargetInventory = Targets.Count switch
        {
            0 => "No enrolled targets",
            1 => "1 enrolled target",
            _ => $"{Targets.Count} enrolled targets",
        };
        SelectedTarget = Targets.FirstOrDefault(
                target => target.TargetId == selectedTargetId) ??
            Targets.FirstOrDefault();

        if (Targets.Count == 0 && acceptedOperationId is null)
        {
            SetLiveUnavailable(
                "No enrolled targets",
                "Enroll one with: certbatonctl target enroll --config <path-to-json>",
                isError: false);
        }

        StartRenewalCommand.NotifyCanExecuteChanged();
        return true;
    }

    private async Task StartRenewalAsync()
    {
        var target = SelectedTarget;
        if (target is null)
        {
            SetLiveUnavailable(
                "No target selected",
                "Select an enrolled target before starting a renewal.",
                isError: false);
            return;
        }

        IsRefreshing = true;
        LiveStatus = "Requesting renewal...";
        LiveSummary =
            "The request is being handed to the service-owned live renewal worker.";
        LiveStatusBrush = CreateBrush(181, 122, 0);

        var idempotencyKey = GetOrCreatePendingRenewalKey(target.TargetId);
        try
        {
            var response = await startRenewalAsync(
                    target.TargetId,
                    idempotencyKey,
                    CancellationToken.None)
                .ConfigureAwait(true);
            if (!response.Success)
            {
                if (IsDefinitiveRenewalStartRejection(response.Error?.Code))
                {
                    pendingRenewalKeys.Remove(target.TargetId);
                }

                ApplyRenewalStartError(response);
                return;
            }

            var operation = response.Result?.RenewalOperation;
            string? validationError = null;
            if (operation is null || !operation.TryValidate(out validationError))
            {
                SetLiveUnavailable(
                    "Renewal response is invalid",
                    validationError ??
                        "The service returned no accepted renewal operation.");
                return;
            }

            if (operation.TargetId != target.TargetId)
            {
                SetLiveUnavailable(
                    "Renewal response mismatch",
                    "The service returned an operation for a different target. The response was not displayed, and a retry will reuse the same request identity.");
                return;
            }

            acceptedOperationId = operation.OperationId;
            acceptedOperationTargetId = target.TargetId;
            pendingRenewalKeys.Remove(target.TargetId);
            ApplyRenewalOperation(operation);

            var pollingRemainedOnAcceptedOperation = true;
            for (var attempt = 0;
                 attempt < RenewalPollAttempts && IsRenewalInProgress(operation.Status);
                 attempt++)
            {
                await renewalPollDelayAsync(
                        renewalPollInterval,
                        CancellationToken.None)
                    .ConfigureAwait(true);
                response = await getRenewalAsync(
                        operation.OperationId,
                        CancellationToken.None)
                    .ConfigureAwait(true);
                if (!ApplyExpectedRenewalResponse(
                        response,
                        operation.OperationId,
                        target.TargetId))
                {
                    pollingRemainedOnAcceptedOperation = false;
                    break;
                }

                operation = response.Result!.RenewalOperation!;
            }

            if (pollingRemainedOnAcceptedOperation &&
                IsRenewalInProgress(operation.Status))
            {
                LiveSummary =
                    $"{BuildRenewalSummary(operation)} Use Refresh to continue tracking this exact operation.";
            }
        }
        catch (Exception exception) when (IsExpectedClientException(exception))
        {
            LiveStatus = exception is UnauthorizedAccessException
                ? "Administrator approval required"
                : "Renewal request unavailable";
            LiveSummary = exception is UnauthorizedAccessException
                ? "Run CertBaton from an elevated administrator session to start a live renewal."
                : $"{exception.Message} A retry will reuse the same renewal request identity for this target.";
            LiveStatusBrush = CreateBrush(184, 50, 50);
        }
        finally
        {
            FinishBusyState();
        }
    }

    private Guid GetOrCreatePendingRenewalKey(Guid targetId)
    {
        if (pendingRenewalKeys.TryGetValue(targetId, out var existing))
        {
            return existing;
        }

        var created = Guid.CreateVersion7();
        pendingRenewalKeys.Add(targetId, created);
        return created;
    }

    private void ApplyRenewalStartError(IpcResponse response)
    {
        var code = response.Error?.Code;
        if (string.Equals(code, "renewal_start_forbidden", StringComparison.Ordinal))
        {
            LiveStatus = "Administrator approval required";
            LiveSummary =
                "Run CertBaton from an elevated administrator session to start a live renewal.";
        }
        else if (string.Equals(
                     code,
                     "renewal_start_unavailable",
                     StringComparison.Ordinal))
        {
            LiveStatus = "Live renewal is not configured";
            LiveSummary = response.Error?.Message ??
                "The installed service does not expose the live renewal worker.";
        }
        else
        {
            LiveStatus = "Renewal was not accepted";
            LiveSummary = response.Error?.Message ??
                "The service returned no renewal diagnostic.";
            if (!IsDefinitiveRenewalStartRejection(code))
            {
                LiveSummary +=
                    " A retry will reuse the same renewal request identity for this target.";
            }
        }

        LiveFailureCode = code ?? UnavailableValue;
        LiveStatusBrush = CreateBrush(184, 50, 50);
    }

    private bool ApplyExpectedRenewalResponse(
        IpcResponse response,
        Guid expectedOperationId,
        Guid expectedTargetId)
    {
        if (!response.Success)
        {
            var code = response.Error?.Code;
            LiveStatus = code is "renewal_get_forbidden"
                ? "Administrator approval required"
                : "Accepted renewal unavailable";
            LiveSummary = code switch
            {
                "renewal_get_forbidden" =>
                    "Run CertBaton from an elevated administrator session to read live renewal evidence.",
                "renewal_not_found" =>
                    $"The service could not find accepted operation {expectedOperationId:D}. No other operation was substituted.",
                _ => response.Error?.Message ??
                    "The accepted renewal operation could not be read.",
            };
            LiveStatusBrush = CreateBrush(184, 50, 50);
            return false;
        }

        var operation = response.Result?.RenewalOperation;
        string? validationError = null;
        if (operation is null || !operation.TryValidate(out validationError))
        {
            SetLiveUnavailable(
                "Renewal data is invalid",
                validationError ??
                    "The service returned no renewal operation data.");
            return false;
        }

        if (operation.OperationId != expectedOperationId ||
            operation.TargetId != expectedTargetId)
        {
            LiveStatus = "Renewal response mismatch";
            LiveSummary =
                $"The service response did not match accepted operation {expectedOperationId:D}. Its status and evidence were not displayed.";
            LiveStatusBrush = CreateBrush(184, 50, 50);
            return false;
        }

        ApplyRenewalOperation(operation);
        return true;
    }

    private void ApplyRenewalOperation(RenewalOperationSnapshot operation)
    {
        LiveStatus = ToDisplayValue(operation.Status);
        LiveSummary = BuildRenewalSummary(operation);
        LiveOperationId = operation.OperationId.ToString(
            "D",
            CultureInfo.InvariantCulture);
        LiveTargetName = Targets.FirstOrDefault(
                target => target.TargetId == operation.TargetId)?.DisplayName ??
            operation.TargetId.ToString("D", CultureInfo.InvariantCulture);
        LiveRequested = FormatLocal(operation.RequestedAtUtc);
        LiveUpdated = FormatLocal(operation.UpdatedAtUtc);
        LiveCompleted = operation.CompletedAtUtc.HasValue
            ? FormatLocal(operation.CompletedAtUtc.Value)
            : UnavailableValue;
        LiveFailureCode = operation.FailureCode ?? UnavailableValue;
        LiveCertificateFingerprint =
            operation.CertificateLeafSha256 ?? UnavailableValue;
        LivePublicTls = operation.PublicTlsVerified
            ? "Verified"
            : "Not verified";
        LiveChallengeCleanup = operation.ChallengeCleanupVerified
            ? "Verified"
            : "Not verified";
        LiveStatusBrush = operation.Status switch
        {
            "succeeded" => CreateBrush(33, 132, 88),
            "failed" or "interrupted" or "rollback-required" =>
                CreateBrush(184, 50, 50),
            "blocked" => CreateBrush(181, 122, 0),
            _ => CreateBrush(181, 122, 0),
        };

        LiveTimeline.Clear();
        foreach (var item in operation.Evidence.OrderBy(static item => item.Sequence))
        {
            LiveTimeline.Add(
                new RenewalTimelineItem(
                    item.Sequence,
                    ToDisplayValue(item.Category),
                    ToDisplayValue(item.Action),
                    ToDisplayValue(item.Outcome),
                    FormatLocal(item.RecordedAtUtc),
                    item.Description,
                    item.Code));
        }
    }

    private static string BuildRenewalSummary(RenewalOperationSnapshot operation) =>
        operation.Status switch
        {
            "queued" =>
                "The service accepted this renewal and durably queued the operation.",
            "running" =>
                "The service is executing the live ACME, SSH, deployment, and verification workflow.",
            "blocked" =>
                "The operation is blocked and needs operator attention. Review the evidence timeline before retrying.",
            "rollback-required" =>
                "The operation requires rollback or recovery. Review the failure code and evidence before changing the target.",
            "succeeded" =>
                "The certificate was deployed, public TLS was verified, and the HTTP-01 challenge was cleaned up.",
            "failed" => operation.FailureCode is null
                ? "The live renewal failed. Review the evidence timeline."
                : $"The live renewal failed with {operation.FailureCode}. Review the evidence timeline.",
            "cancelled" =>
                "The live renewal was cancelled at a recorded boundary.",
            "interrupted" =>
                "Service recovery found an interrupted renewal. Review the durable evidence before retrying.",
            _ => "The live renewal status is not recognized.",
        };

    private void SetReadyStateForSelection()
    {
        if (SelectedTarget is null)
        {
            return;
        }

        LiveStatus = SelectedTarget.Status == "ready"
            ? "Ready to renew"
            : ToDisplayValue(SelectedTarget.Status);
        LiveSummary = SelectedTarget.Status == "ready"
            ? "Start renewal sends a live request to the Windows service. The selected target controls the ACME and SSH destination."
            : "This target is not ready for a live renewal. Update its configuration before starting.";
        LiveTargetName = SelectedTarget.DisplayName;
        LiveStatusBrush = SelectedTarget.Status == "ready"
            ? CreateBrush(33, 132, 88)
            : CreateBrush(181, 122, 0);
    }

    private static string BuildTargetSummary(TargetSnapshot target)
    {
        var dnsNames = string.Join(", ", target.DnsNames);
        var schedule = target.AutoRenew
            ? "automatic renewal enabled"
            : "manual renewal only";
        return
            $"{dnsNames} via {target.Username}@{target.Host}:{target.Port} | {ToDisplayValue(target.CertificateAuthority)} | {schedule}";
    }

    private static bool IsRenewalInProgress(string statusValue) =>
        statusValue is "queued" or "running";

    private static bool IsDefinitiveRenewalStartRejection(string? code) =>
        code is
            "invalid_request" or
            "protocol_version_unsupported" or
            "invalid_deadline" or
            "method_not_found" or
            "renewal_start_forbidden" or
            "renewal_start_unavailable";

    private async Task StartSimulationAsync()
    {
        IsRefreshing = true;
        SimulationStatus = "Queueing simulation...";
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
                if (IsDefinitiveSimulationStartRejection(response.Error?.Code))
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

    private static bool IsDefinitiveSimulationStartRejection(string? code) =>
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

    private void ClearTargets()
    {
        Targets.Clear();
        SelectedTarget = null;
        TargetInventory = "Targets unavailable";
        StartRenewalCommand.NotifyCanExecuteChanged();
    }

    private void SetLiveUnavailable(
        string newStatus,
        string newSummary,
        bool isError = true)
    {
        LiveStatus = newStatus;
        LiveSummary = newSummary;
        LiveStatusBrush = isError
            ? CreateBrush(184, 50, 50)
            : CreateBrush(101, 120, 138);
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
        new(Color.FromRgb(red, green, blue));

    private sealed record PendingSimulationRequest(
        Guid IdempotencyKey,
        string? FailureStage);
}

public sealed record RenewalTimelineItem(
    long Sequence,
    string Category,
    string Action,
    string Outcome,
    string RecordedAt,
    string Description,
    string Code);

public sealed record SimulationFailureChoice(string Label, string? Stage);

public sealed record SimulationTimelineItem(
    long Sequence,
    string Stage,
    string Outcome,
    string RecordedAt,
    string Description,
    string Code);
