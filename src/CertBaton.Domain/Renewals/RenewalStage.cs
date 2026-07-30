namespace CertBaton.Domain.Renewals;

public enum RenewalStage
{
    Preflight = 0,
    Order = 1,
    Challenge = 2,
    Issuance = 3,
    Deployment = 4,
    Activation = 5,
    Verification = 6,
    Cleanup = 7,
}

public static class RenewalPipeline
{
    private static readonly IReadOnlyList<RenewalStage> orderedStages =
        Array.AsReadOnly(
        [
            RenewalStage.Preflight,
            RenewalStage.Order,
            RenewalStage.Challenge,
            RenewalStage.Issuance,
            RenewalStage.Deployment,
            RenewalStage.Activation,
            RenewalStage.Verification,
            RenewalStage.Cleanup,
        ]);

    public static IReadOnlyList<RenewalStage> Stages => orderedStages;
}
