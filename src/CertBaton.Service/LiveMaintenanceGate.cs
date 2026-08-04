namespace CertBaton.Service;

public sealed class LiveMaintenanceGate
{
    private readonly string? markerPath;

    public LiveMaintenanceGate(string? markerPath = null)
    {
        if (markerPath is not null && !Path.IsPathFullyQualified(markerPath))
        {
            throw new ArgumentException(
                "The maintenance marker path must be absolute.",
                nameof(markerPath));
        }

        this.markerPath = markerPath is null
            ? null
            : Path.GetFullPath(markerPath);
    }

    public bool IsPaused =>
        markerPath is not null &&
        (File.Exists(markerPath) || Directory.Exists(markerPath));

    public void ThrowIfPaused()
    {
        if (IsPaused)
        {
            throw new InvalidOperationException(
                "Live certificate work is paused while installation maintenance is in progress.");
        }
    }

    public async Task WaitUntilOpenAsync(CancellationToken cancellationToken)
    {
        while (IsPaused)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken)
                .ConfigureAwait(false);
        }
    }
}
