using System.Text.Json;
using CertBaton.Acme.Anvil;
using CertBaton.Application.Acme;
using CertBaton.Application.Live;
using CertBaton.Application.Persistence;
using CertBaton.Application.Remote;
using CertBaton.Application.Security;
using CertBaton.Application.Simulation;
using CertBaton.Application.Simulation.Persistence;
using CertBaton.Application.Verification;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;
using CertBaton.Persistence.Sqlite;
using CertBaton.Remote.Ssh;
using CertBaton.Security.Windows;
using CertBaton.Service;
using CertBaton.Verification;
using Microsoft.Extensions.Hosting.WindowsServices;

if (args is ["--maintenance-inspect-state", var databasePath])
{
    try
    {
        var snapshot = OfflineProductionStateInspector.Inspect(databasePath);
        Console.WriteLine(JsonSerializer.Serialize(snapshot));
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine(exception.Message);
        Environment.ExitCode = 2;
    }

    return;
}

var builder = Host.CreateApplicationBuilder(args);
var isInstalledWindowsService = WindowsServiceHelpers.IsWindowsService();
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = IpcProtocol.WindowsServiceName;
});

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(
    new LiveMaintenanceGate(
        ServiceStatePath.ResolveMaintenanceMarkerPath(
            isInstalledWindowsService)));
var simulationStageDelay = isInstalledWindowsService
    ? TimeSpan.FromMilliseconds(750)
    : TimeSpan.Zero;
var ipcOptions = new IpcServerOptions
{
    PipeName = IpcProtocol.DefaultPipeName,
    SecurityProfile = isInstalledWindowsService
        ? PipeServerSecurityProfile.InstalledService
        : PipeServerSecurityProfile.CurrentUserDevelopment,
};
builder.Services.AddSingleton(ipcOptions);
builder.Services.AddSingleton<CertBatonPipeServer>();
builder.Services.AddSingleton<SimulationAccessPolicy>();
builder.Services.AddSingleton(
    DpapiNgSecretProtector.ForCurrentUser());
builder.Services.AddSingleton<ISecretVault>(
    services =>
        new ProtectedFileSecretVault(
            ServiceStatePath.ResolveSecretsDirectory(
                isInstalledWindowsService),
            services.GetRequiredService<DpapiNgSecretProtector>()));
builder.Services.AddSingleton<IVaultProbe, VaultProbe>();
builder.Services.AddSingleton<ICredentialImporter, CredentialImporter>();
builder.Services.AddSingleton<IAcmeEngine, AnvilAcmeEngine>();
builder.Services.AddSingleton<IRemoteSshSessionFactory, SshNetSessionFactory>();
builder.Services.AddSingleton<IPublicHttp01Verifier, PublicHttp01Verifier>();
builder.Services.AddSingleton<IPublicTlsVerifier, PublicTlsVerifier>();
builder.Services.AddSingleton<
    ICertificateMaterialInspector,
    CertificateMaterialInspector>();
builder.Services.AddSingleton(
    services =>
        new SimulatedRenewalRunner(
            services.GetRequiredService<TimeProvider>(),
            simulationStageDelay));
builder.Services.AddSingleton<ISimulationJobStore>(
    _ =>
        new SqliteSimulationJobStore(
            ServiceStatePath.ResolveDatabasePath(isInstalledWindowsService)));
builder.Services.AddSingleton<IProductionStore>(
    services =>
    {
        var store = new SqliteProductionStore(
            ServiceStatePath.ResolveDatabasePath(isInstalledWindowsService));
        store.Initialize(
            services.GetRequiredService<TimeProvider>().GetUtcNow());
        return store;
    });
builder.Services.AddSingleton<LiveTargetCoordinator>();
builder.Services.AddSingleton<ILiveTargetCoordinator>(
    static services => services.GetRequiredService<LiveTargetCoordinator>());
builder.Services.AddSingleton<IAcmeAccountStore, VaultBackedAcmeAccountStore>();
builder.Services.AddSingleton<
    ICertificatePrivateKeyStore,
    VaultCertificatePrivateKeyStore>();
builder.Services.AddSingleton<
    IIssuedCertificateStore,
    ProductionIssuedCertificateStore>();
builder.Services.AddSingleton<ILiveRenewalExecutor, ProductionLiveRenewalExecutor>();
builder.Services.AddSingleton<LiveRenewalCoordinator>();
builder.Services.AddSingleton<ILiveRenewalCoordinator>(
    static services => services.GetRequiredService<LiveRenewalCoordinator>());
builder.Services.AddSingleton<SimulationCoordinator>();
builder.Services.AddSingleton<ISimulationCoordinator>(
    static services => services.GetRequiredService<SimulationCoordinator>());
builder.Services.AddHostedService(
    static services => services.GetRequiredService<SimulationCoordinator>());
builder.Services.AddHostedService(
    static services => services.GetRequiredService<LiveRenewalCoordinator>());
builder.Services.AddHostedService<IpcWorker>();

var host = builder.Build();
await host.RunAsync();
