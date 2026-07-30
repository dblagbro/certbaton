using CertBaton.Contracts;
using CertBaton.Desktop;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class MainWindowViewModelTests
{
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
}
