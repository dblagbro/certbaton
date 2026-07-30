namespace CertBaton.Ipc.NamedPipes;

public sealed class IpcProtocolException : Exception
{
    public IpcProtocolException(string message)
        : base(message)
    {
    }

    public IpcProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
