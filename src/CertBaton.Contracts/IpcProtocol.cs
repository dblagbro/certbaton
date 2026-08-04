namespace CertBaton.Contracts;

public static class IpcProtocol
{
    public const int CurrentVersion = 1;
    public const int MaximumFrameBytes = 64 * 1024;
    public const string DefaultPipeName = "CertBaton.Service.v1";
    public const string HealthMethod = "health";
    public const string SimulationLatestMethod = "simulation.latest";
    public const string SimulationStartMethod = "simulation.start";
    public const string VaultProbeMethod = "vault.probe";
    public const string CredentialImportSshPrivateKeyMethod =
        "credential.importSshPrivateKey";
    public const string SshConnectionProbeMethod = "connection.probeSshSftp";
    public const string TargetEnrollMethod = "target.enroll";
    public const string TargetListMethod = "target.list";
    public const string RenewalStartMethod = "renewal.start";
    public const string RenewalGetMethod = "renewal.get";
    public const string WindowsServiceName = "CertBaton";

    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(3);
    public static readonly TimeSpan MaximumRequestHorizon = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan ClockSkewAllowance = TimeSpan.FromSeconds(5);
}
