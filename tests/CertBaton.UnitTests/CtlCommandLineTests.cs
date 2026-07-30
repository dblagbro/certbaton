using System.IO;
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
}
