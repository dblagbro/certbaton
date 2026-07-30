using CertBaton.Domain.Renewals;

namespace CertBaton.Application.Simulation;

public sealed record SimulationFailure
{
    public SimulationFailure(
        RenewalStage stage,
        string code = "simulation.injected_failure",
        string description = "The configured simulated stage failure occurred.")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);

        Stage = stage;
        Code = code;
        Description = description;
    }

    public RenewalStage Stage { get; }

    public string Code { get; }

    public string Description { get; }
}

public sealed record RenewalSimulationPlan
{
    public RenewalSimulationPlan(
        SimulationFailure? failure = null,
        RenewalStage? cancelBeforeStage = null)
    {
        if (failure is not null && cancelBeforeStage.HasValue)
        {
            throw new ArgumentException(
                "A simulation plan cannot inject both failure and cancellation.");
        }

        Failure = failure;
        CancelBeforeStage = cancelBeforeStage;
    }

    public SimulationFailure? Failure { get; }

    public RenewalStage? CancelBeforeStage { get; }
}
