using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;
using CertBaton.Service;
using Microsoft.Extensions.Hosting.WindowsServices;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = IpcProtocol.WindowsServiceName;
});

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(
    new IpcServerOptions
    {
        PipeName = IpcProtocol.DefaultPipeName,
        SecurityProfile = WindowsServiceHelpers.IsWindowsService()
            ? PipeServerSecurityProfile.InstalledService
            : PipeServerSecurityProfile.CurrentUserDevelopment,
    });
builder.Services.AddSingleton<CertBatonPipeServer>();
builder.Services.AddHostedService<IpcWorker>();

var host = builder.Build();
await host.RunAsync();
