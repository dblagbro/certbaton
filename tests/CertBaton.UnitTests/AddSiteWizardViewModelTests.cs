using System.Security.Cryptography;
using CertBaton.Contracts;
using CertBaton.Desktop;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class AddSiteWizardViewModelTests
{
    private static readonly byte[] privateKey =
        "-----BEGIN PRIVATE KEY-----\nunit-test\n-----END PRIVATE KEY-----"u8.ToArray();

    [TestMethod]
    public async Task GuidedFlowTestsConnectionThenEnrollsWebsite()
    {
        var probe = CreateProbe();
        TargetEnrollmentPayload? enrolledPayload = null;
        var imported = false;
        var viewModel = new AddSiteWizardViewModel(
            (host, port, username, key, cancellationToken) =>
            {
                Assert.AreEqual("ssh.example.test", host);
                Assert.AreEqual(22, port);
                Assert.AreEqual("designer", username);
                Assert.IsFalse(cancellationToken.IsCancellationRequested);
                CollectionAssert.AreEqual(privateKey, key.ToArray());
                return Task.FromResult(
                    IpcResponse.Succeeded(Guid.NewGuid(), probe));
            },
            (key, cancellationToken) =>
            {
                Assert.IsFalse(cancellationToken.IsCancellationRequested);
                CollectionAssert.AreEqual(privateKey, key.ToArray());
                imported = true;
                return Task.FromResult(
                    IpcResponse.Succeeded(
                        Guid.NewGuid(),
                        new CredentialImportSnapshot(
                            Guid.Parse("019fcbad-d9ec-7d79-a30a-7f2493a29710"),
                            CredentialContractValues.SshPrivateKeyKind,
                            DateTimeOffset.UtcNow)));
            },
            (payload, cancellationToken) =>
            {
                Assert.IsFalse(cancellationToken.IsCancellationRequested);
                enrolledPayload = payload;
                return Task.FromResult(
                    IpcResponse.Succeeded(
                        Guid.NewGuid(),
                        new TargetSnapshot(
                            payload.EnrollmentId,
                            payload.DisplayName,
                            payload.DnsNames,
                            payload.Host,
                            payload.Port,
                            payload.Username,
                            payload.HostKeyAlgorithm,
                            payload.HostKeyFingerprintSha256,
                            payload.CertificateAuthority,
                            payload.AutoRenew,
                            null,
                            "ready")));
            },
            static (_, _) => Task.FromResult(privateKey.ToArray()));

        Populate(viewModel);
        Assert.IsFalse(viewModel.AddSiteCommand.CanExecute(null));

        await viewModel.TestConnectionCommand.ExecuteAsync(null);

        Assert.IsTrue(viewModel.ConnectionVerified);
        Assert.AreEqual(
            probe.HostKeyFingerprintSha256,
            viewModel.ServerIdentity.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1]);
        Assert.IsFalse(viewModel.AddSiteCommand.CanExecute(null));

        viewModel.ServerIdentityConfirmed = true;
        viewModel.TermsAccepted = true;
        Assert.IsTrue(viewModel.AddSiteCommand.CanExecute(null));

        await viewModel.AddSiteCommand.ExecuteAsync(null);

        Assert.IsTrue(imported);
        Assert.IsTrue(viewModel.IsComplete);
        Assert.IsNotNull(viewModel.CreatedTarget);
        Assert.IsNotNull(enrolledPayload);
        Assert.AreEqual("Restaurant website", enrolledPayload.DisplayName);
        Assert.AreEqual("www.example.test", enrolledPayload.DnsNames.Single());
        Assert.AreEqual(LiveContractValues.LetsEncryptStaging, enrolledPayload.CertificateAuthority);
        Assert.IsFalse(enrolledPayload.AutoRenew);
        Assert.AreEqual(probe.HostKeyBase64, enrolledPayload.HostKeyBase64);
    }

    [TestMethod]
    public async Task ChangingConnectionDetailsRequiresAnotherTest()
    {
        var probe = CreateProbe();
        var viewModel = new AddSiteWizardViewModel(
            static (_, _, _, _, _) => Task.FromResult(
                IpcResponse.Succeeded(Guid.NewGuid(), CreateProbe())),
            static (_, _) => throw new AssertFailedException(
                "A changed connection must not import a key."),
            static (_, _) => throw new AssertFailedException(
                "A changed connection must not enroll a website."),
            static (_, _) => Task.FromResult(privateKey.ToArray()));
        Populate(viewModel);

        await viewModel.TestConnectionCommand.ExecuteAsync(null);
        Assert.IsTrue(viewModel.ConnectionVerified);
        Assert.AreEqual("ssh.example.test", probe.Host);

        viewModel.ServerAddress = "other.example.test";

        Assert.IsFalse(viewModel.ConnectionVerified);
        Assert.IsFalse(viewModel.ServerIdentityConfirmed);
        Assert.AreEqual("Not checked yet", viewModel.ServerIdentity);
        Assert.IsFalse(viewModel.AddSiteCommand.CanExecute(null));
    }

    [TestMethod]
    public async Task FailedTestNeverImportsOrEnrolls()
    {
        var viewModel = new AddSiteWizardViewModel(
            static (_, _, _, _, _) => Task.FromResult(
                IpcResponse.Failed(
                    Guid.NewGuid(),
                    "connection_probe_failed",
                    "The hosting login was rejected.")),
            static (_, _) => throw new AssertFailedException(
                "A failed test must not import a key."),
            static (_, _) => throw new AssertFailedException(
                "A failed test must not enroll a website."),
            static (_, _) => Task.FromResult(privateKey.ToArray()));
        Populate(viewModel);

        await viewModel.TestConnectionCommand.ExecuteAsync(null);

        Assert.IsFalse(viewModel.ConnectionVerified);
        Assert.AreEqual("Connection test failed", viewModel.StatusTitle);
        StringAssert.Contains(viewModel.StatusMessage, "hosting login was rejected");
        Assert.IsFalse(viewModel.AddSiteCommand.CanExecute(null));
    }

    [TestMethod]
    public async Task InvalidWebsiteDetailsNeverImportCredential()
    {
        var viewModel = new AddSiteWizardViewModel(
            static (_, _, _, _, _) => Task.FromResult(
                IpcResponse.Succeeded(Guid.NewGuid(), CreateProbe())),
            static (_, _) => throw new AssertFailedException(
                "Invalid website details must not import a key."),
            static (_, _) => throw new AssertFailedException(
                "Invalid website details must not enroll a website."),
            static (_, _) => Task.FromResult(privateKey.ToArray()));
        Populate(viewModel);

        await viewModel.TestConnectionCommand.ExecuteAsync(null);
        viewModel.ServerIdentityConfirmed = true;
        viewModel.TermsAccepted = true;
        viewModel.ContactEmail = "not an email address";

        await viewModel.AddSiteCommand.ExecuteAsync(null);

        Assert.IsFalse(viewModel.IsComplete);
        Assert.AreEqual("Review the website details", viewModel.StatusTitle);
        StringAssert.Contains(viewModel.StatusMessage, "valid contact email");
    }

    private static void Populate(AddSiteWizardViewModel viewModel)
    {
        viewModel.SiteName = "Restaurant website";
        viewModel.DomainName = "www.example.test";
        viewModel.ContactEmail = "owner@example.test";
        viewModel.ServerAddress = "ssh.example.test";
        viewModel.SshPort = 22;
        viewModel.SshUsername = "designer";
        viewModel.PrivateKeyPath = "C:\\private\\site-key";
    }

    private static SshConnectionProbeSnapshot CreateProbe()
    {
        var hostKey = RandomNumberGenerator.GetBytes(48);
        return new SshConnectionProbeSnapshot(
            LiveContractValues.SshSftpConnector,
            "ssh.example.test",
            22,
            "designer",
            "ssh-ed25519",
            "SHA256:" +
                Convert.ToBase64String(SHA256.HashData(hostKey)).TrimEnd('='),
            Convert.ToBase64String(hostKey),
            AuthenticationSucceeded: true,
            SftpAvailable: true,
            DateTimeOffset.UtcNow);
    }
}
