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
    private string status = "Checking service…";
    private string summary = "Waiting for the local CertBaton service.";
    private string serviceVersion = UnavailableValue;
    private string serviceStarted = UnavailableValue;
    private string lastChecked = "Not checked yet";
    private Brush statusBrush = new SolidColorBrush(Color.FromRgb(181, 122, 0));
    private bool isRefreshing;

    public MainWindowViewModel()
        : this(new CertBatonPipeClient().GetHealthAsync)
    {
    }

    internal MainWindowViewModel(
        Func<CancellationToken, Task<IpcResponse>> getHealthAsync)
    {
        this.getHealthAsync = getHealthAsync;
        RefreshCommand = new AsyncRelayCommand(RefreshAsync, () => !IsRefreshing);
    }

    public IAsyncRelayCommand RefreshCommand { get; }

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

    public bool IsRefreshing
    {
        get => isRefreshing;
        private set
        {
            if (SetProperty(ref isRefreshing, value))
            {
                RefreshCommand.NotifyCanExecuteChanged();
            }
        }
    }

    private async Task RefreshAsync()
    {
        IsRefreshing = true;
        Status = "Checking service…";
        Summary = "Opening the authenticated local service channel.";
        StatusBrush = new SolidColorBrush(Color.FromRgb(181, 122, 0));

        try
        {
            var response = await getHealthAsync(CancellationToken.None).ConfigureAwait(true);
            if (!response.Success || response.Result is null)
            {
                Status = "Service reported a problem";
                Summary = response.Error?.Message ?? "No diagnostic details were returned.";
                ClearServiceDetails();
                StatusBrush = new SolidColorBrush(Color.FromRgb(184, 50, 50));
                return;
            }

            Status = "Service is healthy";
            Summary = "The Windows client can communicate with the local CertBaton service.";
            ServiceVersion = response.Result.ServiceVersion;
            ServiceStarted = response.Result.StartedAtUtc
                .ToLocalTime()
                .ToString("f", CultureInfo.CurrentCulture);
            StatusBrush = new SolidColorBrush(Color.FromRgb(33, 132, 88));
        }
        catch (Exception exception) when (
            exception is IOException or
            TimeoutException or
            UnauthorizedAccessException or
            IpcProtocolException)
        {
            Status = "Service is unavailable";
            Summary = exception.Message;
            ClearServiceDetails();
            StatusBrush = new SolidColorBrush(Color.FromRgb(184, 50, 50));
        }
        finally
        {
            LastChecked = DateTimeOffset.Now.ToString("T", CultureInfo.CurrentCulture);
            IsRefreshing = false;
        }
    }

    private void ClearServiceDetails()
    {
        ServiceVersion = UnavailableValue;
        ServiceStarted = UnavailableValue;
    }
}
