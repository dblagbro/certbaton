using CertBaton.Application.Remote;
using Renci.SshNet.Common;

namespace CertBaton.Remote.Ssh;

internal sealed class SshHostKeyVerifier
{
    private readonly RemoteSshEndpoint _endpoint;
    private readonly SshHostKeyPin _pin;

    internal SshHostKeyVerifier(RemoteSshEndpoint endpoint, SshHostKeyPin pin)
    {
        _endpoint = endpoint;
        _pin = pin;
    }

    internal bool Rejected { get; private set; }

    internal void Handle(object? sender, HostKeyEventArgs eventArgs)
    {
        ArgumentNullException.ThrowIfNull(eventArgs);
        eventArgs.CanTrust = _pin.Matches(_endpoint, eventArgs.HostKeyName, eventArgs.HostKey);
        Rejected |= !eventArgs.CanTrust;
    }
}
