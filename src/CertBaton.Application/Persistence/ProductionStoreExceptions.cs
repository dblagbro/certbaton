namespace CertBaton.Application.Persistence;

public sealed class ProductionOperationAlreadyActiveException : InvalidOperationException
{
    public ProductionOperationAlreadyActiveException()
        : base("Another production operation is already active for this target.")
    {
    }
}

public sealed class ProductionIdempotencyConflictException : InvalidOperationException
{
    public ProductionIdempotencyConflictException()
        : base("The idempotency key is already associated with a different production operation.")
    {
    }
}

public sealed class ProductionOperationInvariantException : InvalidOperationException
{
    public ProductionOperationInvariantException(string message)
        : base(message)
    {
    }

    public ProductionOperationInvariantException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class ProductionOperationStateConflictException : InvalidOperationException
{
    public ProductionOperationStateConflictException()
        : base("The production operation state or execution owner changed concurrently.")
    {
    }
}

public sealed class ProductionOperationIntentStateConflictException : InvalidOperationException
{
    public ProductionOperationIntentStateConflictException()
        : base("The operation intent state or owning execution changed concurrently.")
    {
    }
}

public sealed class ProductionAcmeAccountStateConflictException : InvalidOperationException
{
    public ProductionAcmeAccountStateConflictException()
        : base("The ACME account state changed concurrently.")
    {
    }
}

public sealed class ProductionEnrollmentConflictException : InvalidOperationException
{
    public ProductionEnrollmentConflictException()
        : base("The enrollment identifier is already bound to a different immutable target graph.")
    {
    }
}

public sealed class ProductionCertificateArtifactStateConflictException : InvalidOperationException
{
    public ProductionCertificateArtifactStateConflictException()
        : base("The certificate artifact state changed concurrently.")
    {
    }
}

public sealed class ProductionAuditEventConflictException : InvalidOperationException
{
    public ProductionAuditEventConflictException()
        : base("The audit-event identifier is already bound to different immutable evidence.")
    {
    }
}
