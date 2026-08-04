namespace CertBaton.Contracts;

public sealed record IpcRequest(
    int ProtocolVersion,
    Guid RequestId,
    string Method,
    DateTimeOffset SentAtUtc,
    DateTimeOffset DeadlineUtc,
    SimulationStartPayload? Payload = null,
    CredentialImportPayload? CredentialPayload = null,
    TargetEnrollmentPayload? TargetEnrollmentPayload = null,
    RenewalStartPayload? RenewalStartPayload = null,
    RenewalQueryPayload? RenewalQueryPayload = null)
{
    public static IpcRequest CreateHealth(
        TimeProvider timeProvider,
        TimeSpan? timeout = null) =>
        Create(
            timeProvider,
            IpcProtocol.HealthMethod,
            null,
            timeout);

    public static IpcRequest CreateSimulationLatest(
        TimeProvider timeProvider,
        TimeSpan? timeout = null) =>
        Create(
            timeProvider,
            IpcProtocol.SimulationLatestMethod,
            null,
            timeout);

    public static IpcRequest CreateSimulationStart(
        TimeProvider timeProvider,
        Guid idempotencyKey,
        string? failureStage = null,
        TimeSpan? timeout = null)
    {
        if (idempotencyKey == Guid.Empty)
        {
            throw new ArgumentException(
                "A non-empty simulation idempotency key is required.",
                nameof(idempotencyKey));
        }

        if (failureStage is not null &&
            !SimulationContractValues.IsStage(failureStage))
        {
            throw new ArgumentException(
                $"The simulation failure stage must be one of: {string.Join(", ", SimulationContractValues.Stages)}.",
                nameof(failureStage));
        }

        var payload = new SimulationStartPayload(idempotencyKey, failureStage);
        return Create(
            timeProvider,
            IpcProtocol.SimulationStartMethod,
            payload,
            timeout);
    }

    public static IpcRequest CreateVaultProbe(
        TimeProvider timeProvider,
        TimeSpan? timeout = null) =>
        Create(
            timeProvider,
            IpcProtocol.VaultProbeMethod,
            null,
            timeout);

    public static IpcRequest CreateCredentialImportSshPrivateKey(
        TimeProvider timeProvider,
        ReadOnlySpan<byte> privateKey,
        TimeSpan? timeout = null)
    {
        var payload = new CredentialImportPayload(
            CredentialContractValues.SshPrivateKeyKind,
            privateKey.ToArray());
        if (!payload.TryValidate(out var error))
        {
            throw new ArgumentException(error, nameof(privateKey));
        }

        return Create(
            timeProvider,
            IpcProtocol.CredentialImportSshPrivateKeyMethod,
            null,
            timeout,
            payload);
    }

    public static IpcRequest CreateTargetEnrollment(
        TimeProvider timeProvider,
        TargetEnrollmentPayload payload,
        TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.TryValidate(out var error))
        {
            throw new ArgumentException(error, nameof(payload));
        }

        return Create(
            timeProvider,
            IpcProtocol.TargetEnrollMethod,
            null,
            timeout,
            targetEnrollmentPayload: payload);
    }

    public static IpcRequest CreateTargetList(
        TimeProvider timeProvider,
        TimeSpan? timeout = null) =>
        Create(
            timeProvider,
            IpcProtocol.TargetListMethod,
            null,
            timeout);

    public static IpcRequest CreateRenewalStart(
        TimeProvider timeProvider,
        RenewalStartPayload payload,
        TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.TryValidate(out var error))
        {
            throw new ArgumentException(error, nameof(payload));
        }

        return Create(
            timeProvider,
            IpcProtocol.RenewalStartMethod,
            null,
            timeout,
            renewalStartPayload: payload);
    }

    public static IpcRequest CreateRenewalGet(
        TimeProvider timeProvider,
        RenewalQueryPayload payload,
        TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.TryValidate(out var error))
        {
            throw new ArgumentException(error, nameof(payload));
        }

        return Create(
            timeProvider,
            IpcProtocol.RenewalGetMethod,
            null,
            timeout,
            renewalQueryPayload: payload);
    }

    public bool TryValidateMethodPayload(out string? error)
    {
        switch (Method)
        {
            case IpcProtocol.HealthMethod:
            case IpcProtocol.SimulationLatestMethod:
            case IpcProtocol.VaultProbeMethod:
            case IpcProtocol.TargetListMethod:
                if (CountPayloads() != 0)
                {
                    error = $"Method '{Method}' does not accept a payload.";
                    return false;
                }

                break;

            case IpcProtocol.SimulationStartMethod:
                if (Payload is null || CountPayloads() != 1)
                {
                    error = $"Method '{Method}' requires a payload.";
                    return false;
                }

                if (!Payload.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.CredentialImportSshPrivateKeyMethod:
                if (CredentialPayload is null || CountPayloads() != 1)
                {
                    error = $"Method '{Method}' requires exactly one credential payload.";
                    return false;
                }

                if (!CredentialPayload.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.TargetEnrollMethod:
                if (TargetEnrollmentPayload is null || CountPayloads() != 1)
                {
                    error = $"Method '{Method}' requires exactly one target enrollment payload.";
                    return false;
                }

                if (!TargetEnrollmentPayload.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.RenewalStartMethod:
                if (RenewalStartPayload is null || CountPayloads() != 1)
                {
                    error = $"Method '{Method}' requires exactly one renewal start payload.";
                    return false;
                }

                if (!RenewalStartPayload.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.RenewalGetMethod:
                if (RenewalQueryPayload is null || CountPayloads() != 1)
                {
                    error = $"Method '{Method}' requires exactly one renewal query payload.";
                    return false;
                }

                if (!RenewalQueryPayload.TryValidate(out error))
                {
                    return false;
                }

                break;

            default:
                if (CountPayloads() != 0)
                {
                    error = "An unregistered method cannot carry a typed payload.";
                    return false;
                }

                break;
        }

        error = null;
        return true;
    }

    private static IpcRequest Create(
        TimeProvider timeProvider,
        string method,
        SimulationStartPayload? payload,
        TimeSpan? timeout,
        CredentialImportPayload? credentialPayload = null,
        TargetEnrollmentPayload? targetEnrollmentPayload = null,
        RenewalStartPayload? renewalStartPayload = null,
        RenewalQueryPayload? renewalQueryPayload = null)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        var requestTimeout = timeout ?? IpcProtocol.DefaultRequestTimeout;
        if (requestTimeout <= TimeSpan.Zero ||
            requestTimeout > IpcProtocol.MaximumRequestHorizon)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timeout),
                $"The request timeout must be greater than zero and no more than {IpcProtocol.MaximumRequestHorizon.TotalSeconds:0} seconds.");
        }

        var sentAtUtc = timeProvider.GetUtcNow();
        return new IpcRequest(
            IpcProtocol.CurrentVersion,
            Guid.NewGuid(),
            method,
            sentAtUtc,
            sentAtUtc.Add(requestTimeout),
            payload,
            credentialPayload,
            targetEnrollmentPayload,
            renewalStartPayload,
            renewalQueryPayload);
    }

    private int CountPayloads() =>
        (Payload is null ? 0 : 1) +
        (CredentialPayload is null ? 0 : 1) +
        (TargetEnrollmentPayload is null ? 0 : 1) +
        (RenewalStartPayload is null ? 0 : 1) +
        (RenewalQueryPayload is null ? 0 : 1);
}

public static class CredentialContractValues
{
    public const string SshPrivateKeyKind = "ssh-private-key";
    public const int MaximumSecretBytes = 48 * 1024;
}

public sealed record CredentialImportPayload(
    string Kind,
    byte[] Secret)
{
    public bool TryValidate(out string? error)
    {
        if (Kind != CredentialContractValues.SshPrivateKeyKind)
        {
            error = "The credential kind is not supported.";
            return false;
        }

        if (Secret is null ||
            Secret.Length == 0 ||
            Secret.Length > CredentialContractValues.MaximumSecretBytes)
        {
            error =
                $"An SSH private key must contain between 1 and {CredentialContractValues.MaximumSecretBytes} bytes.";
            return false;
        }

        error = null;
        return true;
    }
}

public sealed record SimulationStartPayload(
    Guid IdempotencyKey,
    string? FailureStage = null)
{
    public bool TryValidate(out string? error)
    {
        if (IdempotencyKey == Guid.Empty)
        {
            error = "A non-empty simulation idempotency key is required.";
            return false;
        }

        if (FailureStage is not null &&
            !SimulationContractValues.IsStage(FailureStage))
        {
            error =
                $"The simulation failure stage must be one of: {string.Join(", ", SimulationContractValues.Stages)}.";
            return false;
        }

        error = null;
        return true;
    }
}
