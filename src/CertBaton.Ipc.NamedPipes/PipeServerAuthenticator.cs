using System.IO.Pipes;
using System.Runtime.InteropServices;
using CertBaton.Contracts;
using Microsoft.Win32.SafeHandles;

namespace CertBaton.Ipc.NamedPipes;

internal static class PipeServerAuthenticator
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const uint ServiceRunning = 0x00000004;

    public static void Authenticate(
        NamedPipeClientStream pipe,
        int? developmentServerProcessId)
    {
        ArgumentNullException.ThrowIfNull(pipe);

        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var actualProcessId))
        {
            throw new PipeServerAuthenticationException(
                "The identity of the local CertBaton pipe server could not be verified.");
        }

        var expectedProcessId = developmentServerProcessId is int processId
            ? checked((uint)processId)
            : GetInstalledServiceProcessId();

        if (actualProcessId != expectedProcessId)
        {
            throw new PipeServerAuthenticationException(
                "The local pipe endpoint is not owned by the expected CertBaton service process.");
        }
    }

    private static uint GetInstalledServiceProcessId()
    {
        using var serviceManager = OpenSCManager(
            null,
            null,
            ScManagerConnect);
        if (serviceManager.IsInvalid)
        {
            throw ServiceUnavailable();
        }

        using var service = OpenService(
            serviceManager,
            IpcProtocol.WindowsServiceName,
            ServiceQueryStatus);
        if (service.IsInvalid)
        {
            throw ServiceUnavailable();
        }

        var statusSize = checked((uint)Marshal.SizeOf<ServiceStatusProcess>());
        if (!QueryServiceStatusEx(
                service,
                ScStatusProcessInfo,
                out var status,
                statusSize,
                out _) ||
            status.CurrentState != ServiceRunning ||
            status.ProcessId == 0)
        {
            throw ServiceUnavailable();
        }

        return status.ProcessId;
    }

    private static PipeServerAuthenticationException ServiceUnavailable() =>
        new("The installed CertBaton Windows Service is not running or could not be authenticated.");

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(
        SafePipeHandle pipe,
        out uint serverProcessId);

    [DllImport(
        "advapi32.dll",
        EntryPoint = "OpenSCManagerW",
        CharSet = CharSet.Unicode,
        ExactSpelling = true,
        SetLastError = true,
        BestFitMapping = false,
        ThrowOnUnmappableChar = true)]
    private static extern SafeServiceHandle OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport(
        "advapi32.dll",
        EntryPoint = "OpenServiceW",
        CharSet = CharSet.Unicode,
        ExactSpelling = true,
        SetLastError = true,
        BestFitMapping = false,
        ThrowOnUnmappableChar = true)]
    private static extern SafeServiceHandle OpenService(
        SafeServiceHandle serviceManager,
        string serviceName,
        uint desiredAccess);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        SafeServiceHandle service,
        int infoLevel,
        out ServiceStatusProcess serviceStatus,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(nint serviceHandle);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeServiceHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }
}
