namespace CertBaton.Application.Simulation.Persistence;

public sealed class SimulationJobAlreadyActiveException : InvalidOperationException
{
    public SimulationJobAlreadyActiveException()
        : base("Another simulation job is already queued or running.")
    {
    }
}

public sealed class SimulationIdempotencyConflictException : InvalidOperationException
{
    public SimulationIdempotencyConflictException()
        : base("The idempotency key is already associated with a different simulation plan.")
    {
    }
}
