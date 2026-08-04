namespace CertBaton.Application.Acme;

public sealed class AcmeEngineException : Exception
{
    public AcmeEngineException(
        string operation,
        string message,
        AcmeProblem? problem = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);
        Operation = operation;
        Problem = problem;
    }

    public string Operation { get; }

    public AcmeProblem? Problem { get; }
}
