namespace CertBaton.Ipc.NamedPipes;

public sealed class PipeServerAuthenticationException : UnauthorizedAccessException
{
    public PipeServerAuthenticationException(string message)
        : base(message)
    {
    }
}
