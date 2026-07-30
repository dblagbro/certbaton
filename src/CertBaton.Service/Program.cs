using CertBaton.Application.Simulation;
using CertBaton.Application.Simulation.Persistence;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;
using CertBaton.Persistence.Sqlite;
using CertBaton.Service;
using Microsoft.Extensions.Hosting.WindowsServices;

var builder = Host.CreateApplicationBuilder(args);
var isInstalledWindowsService = WindowsServiceHelpers.IsWindowsService();
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = IpcProtocol.WindowsServiceName;
});

builder.Services.AddSingleton(TimeProvider.System);
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
builder.Services.AddSingleton<SimulatedRenewalRunner>();
builder.Services.AddSingleton<ISimulationJobStore>(
    _ =>
        new SqliteSimulationJobStore(
            ServiceStatePath.ResolveDatabasePath(isInstalledWindowsService)));
builder.Services.AddSingleton<SimulationCoordinator>();
builder.Services.AddSingleton<ISimulationCoordinator>(
    static services => services.GetRequiredService<SimulationCoordinator>());
builder.Services.AddHostedService(
    static services => services.GetRequiredService<SimulationCoordinator>());
builder.Services.AddHostedService<IpcWorker>();

var host = builder.Build();
await host.RunAsync();
