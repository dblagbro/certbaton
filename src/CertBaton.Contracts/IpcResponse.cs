using System.Text.Json.Serialization;

namespace CertBaton.Contracts;

public sealed record IpcResponse(
    int ProtocolVersion,
    Guid RequestId,
    bool Success,
    IpcResultEnvelope? Result,
    IpcError? Error)
{
    public static IpcResponse Succeeded(Guid requestId, HealthSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(result, null, null),
            null);
    }

    public static IpcResponse Succeeded(
        Guid requestId,
        SimulationRunSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(null, result, null),
            null);
    }

    public static IpcResponse Succeeded(
        Guid requestId,
        VaultProbeSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(null, null, result),
            null);
    }

    public static IpcResponse Succeeded(
        Guid requestId,
        CredentialImportSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(null, null, null, result),
            null);
    }

    public static IpcResponse Succeeded(
        Guid requestId,
        SshConnectionProbeSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(
                null,
                null,
                null,
                SshConnectionProbe: result),
            null);
    }

    public static IpcResponse Succeeded(Guid requestId, TargetSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(
                null,
                null,
                null,
                null,
                result),
            null);
    }

    public static IpcResponse Succeeded(
        Guid requestId,
        TargetListSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(
                null,
                null,
                null,
                null,
                null,
                result),
            null);
    }

    public static IpcResponse Succeeded(
        Guid requestId,
        RenewalOperationSnapshot result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new IpcResponse(
            IpcProtocol.CurrentVersion,
            requestId,
            true,
            new IpcResultEnvelope(
                null,
                null,
                null,
                null,
                null,
                null,
                result),
            null);
    }

    public static IpcResponse Failed(Guid requestId, string code, string message) =>
        new(
            IpcProtocol.CurrentVersion,
            requestId,
            false,
            null,
            new IpcError(code, message));

    public bool TryValidateForMethod(string method, out string? error)
    {
        if (!Success)
        {
            if (Result is not null || Error is null)
            {
                error = "A failed response must contain an error and no result.";
                return false;
            }

            error = null;
            return true;
        }

        if (Error is not null || Result is null)
        {
            error = "A successful response must contain a result and no error.";
            return false;
        }

        var payloadCount =
            (Result.Health is null ? 0 : 1) +
            (Result.SimulationRun is null ? 0 : 1) +
            (Result.VaultProbe is null ? 0 : 1) +
            (Result.CredentialImport is null ? 0 : 1) +
            (Result.SshConnectionProbe is null ? 0 : 1) +
            (Result.Target is null ? 0 : 1) +
            (Result.TargetList is null ? 0 : 1) +
            (Result.RenewalOperation is null ? 0 : 1);
        if (payloadCount != 1)
        {
            error =
                "A successful response result must contain exactly one typed payload.";
            return false;
        }

        switch (method)
        {
            case IpcProtocol.HealthMethod:
                if (Result.Health is null)
                {
                    error = "A health request must return a health result.";
                    return false;
                }

                break;

            case IpcProtocol.CredentialImportSshPrivateKeyMethod:
                if (Result.CredentialImport is null)
                {
                    error = "A credential import request must return a valid result.";
                    return false;
                }

                if (!Result.CredentialImport.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.SshConnectionProbeMethod:
                if (Result.SshConnectionProbe is null)
                {
                    error = "An SSH/SFTP connection test must return a valid result.";
                    return false;
                }

                if (!Result.SshConnectionProbe.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.VaultProbeMethod:
                if (Result.VaultProbe is null)
                {
                    error = "A vault probe request must return a valid vault probe result.";
                    return false;
                }

                if (!Result.VaultProbe.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.SimulationStartMethod:
            case IpcProtocol.SimulationLatestMethod:
                if (Result.SimulationRun is null)
                {
                    error =
                        "A simulation request must return a simulation run result.";
                    return false;
                }

                if (!Result.SimulationRun.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.TargetEnrollMethod:
                if (Result.Target is null)
                {
                    error = "A target enrollment must return a valid target.";
                    return false;
                }

                if (!Result.Target.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.TargetListMethod:
                if (Result.TargetList is null)
                {
                    error = "A target list request must return a valid list.";
                    return false;
                }

                if (!Result.TargetList.TryValidate(out error))
                {
                    return false;
                }

                break;

            case IpcProtocol.RenewalStartMethod:
            case IpcProtocol.RenewalGetMethod:
                if (Result.RenewalOperation is null)
                {
                    error = "A renewal request must return a valid operation.";
                    return false;
                }

                if (!Result.RenewalOperation.TryValidate(out error))
                {
                    return false;
                }

                break;

            default:
                error = "An unregistered method cannot return a successful result.";
                return false;
        }

        error = null;
        return true;
    }
}

public sealed record IpcError(string Code, string Message);

public sealed record IpcResultEnvelope(
    HealthSnapshot? Health,
    SimulationRunSnapshot? SimulationRun,
    VaultProbeSnapshot? VaultProbe = null,
    CredentialImportSnapshot? CredentialImport = null,
    TargetSnapshot? Target = null,
    TargetListSnapshot? TargetList = null,
    RenewalOperationSnapshot? RenewalOperation = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    SshConnectionProbeSnapshot? SshConnectionProbe = null);

public sealed record HealthSnapshot(
    string Status,
    string ServiceVersion,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset RespondedAtUtc);

public sealed record VaultProbeSnapshot(
    string Status,
    bool RoundTripVerified,
    bool TemporaryRecordRemoved,
    DateTimeOffset CheckedAtUtc)
{
    public bool TryValidate(out string? error)
    {
        if (Status is not "healthy" and not "failed" ||
            CheckedAtUtc == default ||
            CheckedAtUtc.Offset != TimeSpan.Zero)
        {
            error = "The vault probe status or timestamp is invalid.";
            return false;
        }

        if (Status == "healthy" &&
            (!RoundTripVerified || !TemporaryRecordRemoved))
        {
            error = "A healthy vault probe must verify the round trip and remove its temporary record.";
            return false;
        }

        error = null;
        return true;
    }
}

public sealed record CredentialImportSnapshot(
    Guid CredentialReference,
    string Kind,
    DateTimeOffset StoredAtUtc)
{
    public bool TryValidate(out string? error)
    {
        if (CredentialReference == Guid.Empty ||
            Kind != CredentialContractValues.SshPrivateKeyKind ||
            StoredAtUtc == default ||
            StoredAtUtc.Offset != TimeSpan.Zero)
        {
            error = "The credential import result is invalid.";
            return false;
        }

        error = null;
        return true;
    }
}
