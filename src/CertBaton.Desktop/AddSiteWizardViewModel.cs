using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Media;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CertBaton.Desktop;

public sealed class AddSiteWizardViewModel : ObservableObject
{
    private const int MaximumPrivateKeyBytes =
        CredentialContractValues.MaximumSecretBytes;
    private readonly Func<
        string,
        int,
        string,
        ReadOnlyMemory<byte>,
        CancellationToken,
        Task<IpcResponse>> probeConnectionAsync;
    private readonly Func<
        ReadOnlyMemory<byte>,
        CancellationToken,
        Task<IpcResponse>> importPrivateKeyAsync;
    private readonly Func<
        TargetEnrollmentPayload,
        CancellationToken,
        Task<IpcResponse>> enrollTargetAsync;
    private readonly Func<string, CancellationToken, Task<byte[]>> readFileAsync;
    private string siteName = string.Empty;
    private string domainName = string.Empty;
    private string contactEmail = string.Empty;
    private string serverAddress = string.Empty;
    private string sshPortText = "22";
    private string sshUsername = string.Empty;
    private string privateKeyPath = string.Empty;
    private string challengeWebroot =
        "/var/www/certbaton-challenge/.well-known/acme-challenge";
    private string incomingRoot = "/var/lib/certbaton/incoming";
    private string certificatePath =
        "/etc/certbaton/releases/current/fullchain.pem";
    private string privateKeyRemotePath =
        "/etc/certbaton/releases/current/privkey.pem";
    private bool termsAccepted;
    private bool autoRenew;
    private bool serverIdentityConfirmed;
    private bool isBusy;
    private bool connectionVerified;
    private string statusTitle = "Enter your website and hosting details";
    private string statusMessage =
        "CertBaton will test the connection before saving anything.";
    private Brush statusBrush = CreateBrush(29, 91, 121);
    private string serverIdentity = "Not checked yet";
    private SshConnectionProbeSnapshot? verifiedProbe;
    private byte[]? verifiedPrivateKeyHash;

    public AddSiteWizardViewModel()
        : this(new CertBatonPipeClient())
    {
    }

    private AddSiteWizardViewModel(CertBatonPipeClient client)
        : this(
            client.ProbeSshConnectionAsync,
            client.ImportSshPrivateKeyAsync,
            client.EnrollTargetAsync,
            static (path, cancellationToken) =>
                File.ReadAllBytesAsync(path, cancellationToken))
    {
    }

    internal AddSiteWizardViewModel(
        Func<
            string,
            int,
            string,
            ReadOnlyMemory<byte>,
            CancellationToken,
            Task<IpcResponse>> probeConnectionAsync,
        Func<
            ReadOnlyMemory<byte>,
            CancellationToken,
            Task<IpcResponse>> importPrivateKeyAsync,
        Func<
            TargetEnrollmentPayload,
            CancellationToken,
            Task<IpcResponse>> enrollTargetAsync,
        Func<string, CancellationToken, Task<byte[]>> readFileAsync)
    {
        this.probeConnectionAsync = probeConnectionAsync;
        this.importPrivateKeyAsync = importPrivateKeyAsync;
        this.enrollTargetAsync = enrollTargetAsync;
        this.readFileAsync = readFileAsync;
        TestConnectionCommand = new AsyncRelayCommand(
            TestConnectionAsync,
            CanTestConnection);
        AddSiteCommand = new AsyncRelayCommand(AddSiteAsync, CanAddSite);
    }

    public IAsyncRelayCommand TestConnectionCommand { get; }

    public IAsyncRelayCommand AddSiteCommand { get; }

    public TargetSnapshot? CreatedTarget { get; private set; }

    public bool IsComplete => CreatedTarget is not null;

    public string SiteName
    {
        get => siteName;
        set => SetEnrollmentInput(ref siteName, value);
    }

    public string DomainName
    {
        get => domainName;
        set => SetEnrollmentInput(ref domainName, value);
    }

    public string ContactEmail
    {
        get => contactEmail;
        set => SetEnrollmentInput(ref contactEmail, value);
    }

    public string ServerAddress
    {
        get => serverAddress;
        set => SetConnectionInput(ref serverAddress, value);
    }

    public int SshPort
    {
        get => int.TryParse(sshPortText, out var port) ? port : 0;
        set => SshPortText = value.ToString(CultureInfo.InvariantCulture);
    }

    public string SshPortText
    {
        get => sshPortText;
        set
        {
            if (SetProperty(ref sshPortText, value))
            {
                OnPropertyChanged(nameof(SshPort));
                InvalidateConnectionTest();
            }
        }
    }

    public string SshUsername
    {
        get => sshUsername;
        set => SetConnectionInput(ref sshUsername, value);
    }

    public string PrivateKeyPath
    {
        get => privateKeyPath;
        set => SetConnectionInput(ref privateKeyPath, value);
    }

    public string ChallengeWebroot
    {
        get => challengeWebroot;
        set => SetEnrollmentInput(ref challengeWebroot, value);
    }

    public string IncomingRoot
    {
        get => incomingRoot;
        set => SetEnrollmentInput(ref incomingRoot, value);
    }

    public string CertificatePath
    {
        get => certificatePath;
        set => SetEnrollmentInput(ref certificatePath, value);
    }

    public string PrivateKeyRemotePath
    {
        get => privateKeyRemotePath;
        set => SetEnrollmentInput(ref privateKeyRemotePath, value);
    }

    public bool TermsAccepted
    {
        get => termsAccepted;
        set
        {
            if (SetProperty(ref termsAccepted, value))
            {
                AddSiteCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool AutoRenew
    {
        get => autoRenew;
        set => SetProperty(ref autoRenew, value);
    }

    public bool ServerIdentityConfirmed
    {
        get => serverIdentityConfirmed;
        set
        {
            if (SetProperty(ref serverIdentityConfirmed, value))
            {
                AddSiteCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool IsBusy
    {
        get => isBusy;
        private set
        {
            if (SetProperty(ref isBusy, value))
            {
                TestConnectionCommand.NotifyCanExecuteChanged();
                AddSiteCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool ConnectionVerified
    {
        get => connectionVerified;
        private set
        {
            if (SetProperty(ref connectionVerified, value))
            {
                OnPropertyChanged(nameof(ConnectionNeedsTesting));
                AddSiteCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool ConnectionNeedsTesting => !ConnectionVerified;

    public string StatusTitle
    {
        get => statusTitle;
        private set => SetProperty(ref statusTitle, value);
    }

    public string StatusMessage
    {
        get => statusMessage;
        private set => SetProperty(ref statusMessage, value);
    }

    public Brush StatusBrush
    {
        get => statusBrush;
        private set => SetProperty(ref statusBrush, value);
    }

    public string ServerIdentity
    {
        get => serverIdentity;
        private set => SetProperty(ref serverIdentity, value);
    }

    private bool CanTestConnection() =>
        !IsBusy &&
        !string.IsNullOrWhiteSpace(ServerAddress) &&
        int.TryParse(
            SshPortText,
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var port) &&
        port is >= 1 and <= 65_535 &&
        !string.IsNullOrWhiteSpace(SshUsername) &&
        !string.IsNullOrWhiteSpace(PrivateKeyPath);

    private bool CanAddSite() =>
        !IsBusy &&
        ConnectionVerified &&
        ServerIdentityConfirmed &&
        TermsAccepted &&
        !string.IsNullOrWhiteSpace(SiteName) &&
        !string.IsNullOrWhiteSpace(DomainName) &&
        !string.IsNullOrWhiteSpace(ContactEmail) &&
        !string.IsNullOrWhiteSpace(ChallengeWebroot) &&
        !string.IsNullOrWhiteSpace(IncomingRoot) &&
        !string.IsNullOrWhiteSpace(CertificatePath) &&
        !string.IsNullOrWhiteSpace(PrivateKeyRemotePath);

    private async Task TestConnectionAsync()
    {
        IsBusy = true;
        StatusTitle = "Testing the hosting connection...";
        StatusMessage =
            "Signing in securely and checking that SFTP is available. Nothing will be changed on the server.";
        StatusBrush = CreateBrush(181, 122, 0);
        byte[]? privateKey = null;
        try
        {
            privateKey = await ReadPrivateKeyAsync().ConfigureAwait(true);
            var privateKeyHash = SHA256.HashData(privateKey);
            var response = await probeConnectionAsync(
                    ServerAddress,
                    int.Parse(SshPortText, CultureInfo.InvariantCulture),
                    SshUsername,
                    privateKey,
                    CancellationToken.None)
                .ConfigureAwait(true);
            if (!response.Success)
            {
                SetFailure(
                    "Connection test failed",
                    response.Error?.Message ??
                        "CertBaton could not connect with these details.");
                return;
            }

            var probe = response.Result?.SshConnectionProbe;
            string? validationError = null;
            if (probe is null || !probe.TryValidate(out validationError))
            {
                SetFailure(
                    "Connection test returned invalid data",
                    validationError ??
                        "The Service did not return a usable server identity.");
                return;
            }

            verifiedProbe = probe;
            verifiedPrivateKeyHash = privateKeyHash;
            ConnectionVerified = true;
            ServerIdentityConfirmed = false;
            ServerIdentity =
                $"{probe.HostKeyAlgorithm}  {probe.HostKeyFingerprintSha256}";
            StatusTitle = "Connection successful";
            StatusMessage =
                "The key signed in successfully and SFTP is available. Confirm that this server identity belongs to your host before adding the website.";
            StatusBrush = CreateBrush(33, 132, 88);
        }
        catch (Exception exception) when (
            exception is IOException or
            UnauthorizedAccessException or
            ArgumentException or
            IpcProtocolException or
            TimeoutException)
        {
            SetFailure("Connection test failed", exception.Message);
        }
        finally
        {
            if (privateKey is not null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }

            IsBusy = false;
        }
    }

    private async Task AddSiteAsync()
    {
        if (verifiedProbe is null || verifiedPrivateKeyHash is null)
        {
            SetFailure(
                "Test the connection first",
                "CertBaton must verify the current connection details before adding this website.");
            return;
        }

        IsBusy = true;
        StatusTitle = "Adding your website...";
        StatusMessage =
            "Protecting the SSH key and saving the renewal settings in the Windows Service.";
        StatusBrush = CreateBrush(181, 122, 0);
        byte[]? privateKey = null;
        try
        {
            privateKey = await ReadPrivateKeyAsync().ConfigureAwait(true);
            var currentHash = SHA256.HashData(privateKey);
            if (!CryptographicOperations.FixedTimeEquals(
                    currentHash,
                    verifiedPrivateKeyHash))
            {
                InvalidateConnectionTest();
                SetFailure(
                    "The selected key changed",
                    "Test the connection again before adding this website.");
                return;
            }

            var enrollmentId = Guid.CreateVersion7();
            var placeholderCredentialReference = Guid.CreateVersion7();
            var payload = CreateEnrollmentPayload(
                enrollmentId,
                placeholderCredentialReference);
            if (!payload.TryValidate(out var payloadError))
            {
                SetFailure(
                    "Review the website details",
                    payloadError ?? "The website settings are incomplete.");
                return;
            }

            var importResponse = await importPrivateKeyAsync(
                    privateKey,
                    CancellationToken.None)
                .ConfigureAwait(true);
            var credential = importResponse.Result?.CredentialImport;
            string? credentialError = null;
            if (!importResponse.Success ||
                credential is null ||
                !credential.TryValidate(out credentialError))
            {
                SetFailure(
                    "The SSH key could not be protected",
                    importResponse.Error?.Message ?? credentialError ??
                        "The Service returned no credential reference.");
                return;
            }

            payload = payload with
            {
                CredentialReference = credential.CredentialReference,
            };

            var enrollmentResponse = await enrollTargetAsync(
                    payload,
                    CancellationToken.None)
                .ConfigureAwait(true);
            var target = enrollmentResponse.Result?.Target;
            string? targetError = null;
            if (!enrollmentResponse.Success ||
                target is null ||
                !target.TryValidate(out targetError))
            {
                SetFailure(
                    "The website could not be added",
                    enrollmentResponse.Error?.Message ?? targetError ??
                        "The Service returned no website inventory record.");
                return;
            }

            CreatedTarget = target;
            OnPropertyChanged(nameof(CreatedTarget));
            OnPropertyChanged(nameof(IsComplete));
            StatusTitle = "Website added";
            StatusMessage =
                $"{target.DisplayName} is now in CertBaton's inventory. Automatic renewal is {(target.AutoRenew ? "enabled" : "off until you enable it")}.";
            StatusBrush = CreateBrush(33, 132, 88);
        }
        catch (Exception exception) when (
            exception is IOException or
            UnauthorizedAccessException or
            ArgumentException or
            IpcProtocolException or
            TimeoutException)
        {
            SetFailure("The website could not be added", exception.Message);
        }
        finally
        {
            if (privateKey is not null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }

            IsBusy = false;
        }
    }

    private async Task<byte[]> ReadPrivateKeyAsync()
    {
        if (string.IsNullOrWhiteSpace(PrivateKeyPath))
        {
            throw new ArgumentException("Choose an SSH private-key file.");
        }

        var bytes = await readFileAsync(
                PrivateKeyPath,
                CancellationToken.None)
            .ConfigureAwait(true);
        if (bytes.Length is < 1 or > MaximumPrivateKeyBytes)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException(
                $"The selected key file must be no larger than {MaximumPrivateKeyBytes / 1024} KB.");
        }

        return bytes;
    }

    private TargetEnrollmentPayload CreateEnrollmentPayload(
        Guid enrollmentId,
        Guid credentialReference) =>
        new(
            enrollmentId,
            SiteName.Trim(),
            [DomainName.Trim()],
            verifiedProbe!.Host,
            verifiedProbe.Port,
            verifiedProbe.Username,
            credentialReference,
            verifiedProbe.HostKeyAlgorithm,
            verifiedProbe.HostKeyFingerprintSha256,
            verifiedProbe.HostKeyBase64,
            ChallengeWebroot.Trim(),
            IncomingRoot.Trim(),
            CertificatePath.Trim(),
            PrivateKeyRemotePath.Trim(),
            LiveContractValues.LetsEncryptStaging,
            ContactEmail.Trim(),
            TermsAccepted,
            AutoRenew,
            30,
            360);

    private void SetConnectionInput(ref string field, string value)
    {
        if (SetProperty(ref field, value))
        {
            InvalidateConnectionTest();
        }
    }

    private void SetEnrollmentInput(ref string field, string value)
    {
        if (SetProperty(ref field, value))
        {
            AddSiteCommand.NotifyCanExecuteChanged();
        }
    }

    private void InvalidateConnectionTest()
    {
        verifiedProbe = null;
        verifiedPrivateKeyHash = null;
        ConnectionVerified = false;
        ServerIdentityConfirmed = false;
        ServerIdentity = "Not checked yet";
        TestConnectionCommand.NotifyCanExecuteChanged();
        AddSiteCommand.NotifyCanExecuteChanged();
    }

    private void SetFailure(string title, string message)
    {
        StatusTitle = title;
        StatusMessage = message;
        StatusBrush = CreateBrush(184, 50, 50);
    }

    private static SolidColorBrush CreateBrush(byte red, byte green, byte blue) =>
        new SolidColorBrush(Color.FromRgb(red, green, blue));
}
