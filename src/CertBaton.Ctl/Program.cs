using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;

namespace CertBaton.Ctl;

internal static class Program
{
    private static readonly JsonSerializerOptions jsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
        };
    private static readonly JsonSerializerOptions inputJsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            MaxDepth = 16,
            PropertyNameCaseInsensitive = false,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };

    private static Task<int> Main(string[] arguments) =>
        RunAsync(arguments, Console.Out, Console.Error);

    internal static async Task<int> RunAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<Task<IpcResponse>>? getHealthAsync = null,
        Func<Task<IpcResponse>>? getLatestSimulationAsync = null,
        Func<Guid, string?, Task<IpcResponse>>? startSimulationAsync = null,
        Func<Task<IpcResponse>>? probeVaultAsync = null,
        Func<ReadOnlyMemory<byte>, Task<IpcResponse>>?
            importSshPrivateKeyAsync = null,
        Func<TargetEnrollmentPayload, Task<IpcResponse>>?
            enrollTargetAsync = null,
        Func<Task<IpcResponse>>? listTargetsAsync = null,
        Func<Guid, Guid, Task<IpcResponse>>? startRenewalAsync = null,
        Func<Guid, Task<IpcResponse>>? getRenewalAsync = null)
    {
        var unknownSwitch = arguments.FirstOrDefault(
            static argument =>
                argument.StartsWith('-') &&
                argument is not "-h" and
                not "--help" and
                not "--json" and
                not "--fail-stage" and
                not "--idempotency-key" and
                not "--file" and
                not "--config" and
                not "--target-id" and
                not "--operation-id");
        if (unknownSwitch is not null)
        {
            error.WriteLine($"Unknown option: {unknownSwitch}");
            PrintUsage(error);
            return 2;
        }

        if (arguments.Any(static argument => argument is "-h" or "--help"))
        {
            PrintUsage(output);
            return 0;
        }

        if (!TryParseArguments(arguments, out var options, out var argumentError))
        {
            error.WriteLine(argumentError);
            PrintUsage(error);
            return 2;
        }

        try
        {
            CertBatonPipeClient? client = null;
            IpcResponse response;
            switch (options.Command)
            {
                case Command.Health:
                    getHealthAsync ??=
                        () => (client ??= new CertBatonPipeClient()).GetHealthAsync();
                    response = await getHealthAsync().ConfigureAwait(false);
                    break;
                case Command.SimulationLatest:
                    getLatestSimulationAsync ??=
                        () => (client ??= new CertBatonPipeClient()).GetLatestSimulationAsync();
                    response = await getLatestSimulationAsync().ConfigureAwait(false);
                    break;
                case Command.SimulationStart:
                    startSimulationAsync ??=
                        (idempotencyKey, failureStage) =>
                            (client ??= new CertBatonPipeClient()).StartSimulationAsync(
                                idempotencyKey,
                                failureStage);
                    response = await startSimulationAsync(
                            options.IdempotencyKey ?? Guid.CreateVersion7(),
                            options.FailureStage)
                        .ConfigureAwait(false);
                    break;
                case Command.VaultProbe:
                    probeVaultAsync ??=
                        () => (client ??= new CertBatonPipeClient()).ProbeVaultAsync();
                    response = await probeVaultAsync().ConfigureAwait(false);
                    break;
                case Command.CredentialImportSshPrivateKey:
                    importSshPrivateKeyAsync ??=
                        privateKey =>
                            (client ??= new CertBatonPipeClient())
                            .ImportSshPrivateKeyAsync(privateKey);
                    response = await ImportSshPrivateKeyAsync(
                            options.FilePath ??
                                throw new InvalidOperationException(
                                    "A parsed SSH key import did not contain a file path."),
                            importSshPrivateKeyAsync)
                        .ConfigureAwait(false);
                    break;
                case Command.TargetEnroll:
                    enrollTargetAsync ??=
                        payload =>
                            (client ??= new CertBatonPipeClient())
                            .EnrollTargetAsync(payload);
                    response = await EnrollTargetAsync(
                            options.ConfigPath ??
                                throw new InvalidOperationException(
                                    "A parsed target enrollment did not contain a configuration path."),
                            enrollTargetAsync)
                        .ConfigureAwait(false);
                    break;
                case Command.TargetList:
                    listTargetsAsync ??=
                        () => (client ??= new CertBatonPipeClient()).ListTargetsAsync();
                    response = await listTargetsAsync().ConfigureAwait(false);
                    break;
                case Command.RenewalStart:
                    startRenewalAsync ??=
                        (targetId, idempotencyKey) =>
                            (client ??= new CertBatonPipeClient()).StartRenewalAsync(
                                targetId,
                                idempotencyKey);
                    response = await startRenewalAsync(
                            options.TargetId ??
                                throw new InvalidOperationException(
                                    "A parsed renewal start did not contain a target ID."),
                            options.IdempotencyKey ?? Guid.CreateVersion7())
                        .ConfigureAwait(false);
                    break;
                case Command.RenewalGet:
                    getRenewalAsync ??=
                        operationId =>
                            (client ??= new CertBatonPipeClient())
                            .GetRenewalAsync(operationId);
                    response = await getRenewalAsync(
                            options.OperationId ??
                                throw new InvalidOperationException(
                                    "A parsed renewal query did not contain an operation ID."))
                        .ConfigureAwait(false);
                    break;
                default:
                    throw new InvalidOperationException(
                        $"The command '{options.Command}' is not supported.");
            }

            if (!response.Success)
            {
                WriteServiceError(error, response);
                return 1;
            }

            if (options.Command == Command.Health)
            {
                var health = response.Result?.Health;
                if (health is null)
                {
                    WriteServiceError(error, response);
                    return 1;
                }

                WriteHealth(output, health, options.OutputJson);
            }
            else if (options.Command is
                     Command.SimulationLatest or Command.SimulationStart)
            {
                var simulationRun = response.Result?.SimulationRun;
                if (simulationRun is null)
                {
                    WriteServiceError(error, response);
                    return 1;
                }

                WriteSimulationRun(output, simulationRun, options.OutputJson);
            }
            else if (options.Command == Command.VaultProbe)
            {
                var vaultProbe = response.Result?.VaultProbe;
                if (vaultProbe is null)
                {
                    WriteServiceError(error, response);
                    return 1;
                }

                WriteVaultProbe(output, vaultProbe, options.OutputJson);
            }
            else if (options.Command == Command.CredentialImportSshPrivateKey)
            {
                var credential = response.Result?.CredentialImport;
                if (credential is null)
                {
                    WriteServiceError(error, response);
                    return 1;
                }

                WriteCredentialImport(
                    output,
                    credential,
                    options.OutputJson);
            }
            else if (options.Command == Command.TargetEnroll)
            {
                var target = response.Result?.Target;
                if (target is null)
                {
                    WriteServiceError(error, response);
                    return 1;
                }

                WriteTarget(output, target, options.OutputJson);
            }
            else if (options.Command == Command.TargetList)
            {
                var targets = response.Result?.TargetList;
                if (targets is null)
                {
                    WriteServiceError(error, response);
                    return 1;
                }

                WriteTargetList(output, targets, options.OutputJson);
            }
            else
            {
                var operation = response.Result?.RenewalOperation;
                if (operation is null)
                {
                    WriteServiceError(error, response);
                    return 1;
                }

                WriteRenewal(output, operation, options.OutputJson);
            }

            return 0;
        }
        catch (InvalidDataException exception)
        {
            error.WriteLine($"Invalid input: {exception.Message}");
            return 2;
        }
        catch (Exception exception) when (
            exception is IOException or
            TimeoutException or
            UnauthorizedAccessException or
            IpcProtocolException)
        {
            error.WriteLine($"Unable to reach the CertBaton service: {exception.Message}");
            return 3;
        }
    }

    private static bool TryParseArguments(
        IReadOnlyList<string> arguments,
        out CommandLineOptions options,
        out string? error)
    {
        var positionalArguments = new List<string>();
        var outputJson = false;
        var failureStageSpecified = false;
        var idempotencyKeySpecified = false;
        var fileSpecified = false;
        var configSpecified = false;
        var targetIdSpecified = false;
        var operationIdSpecified = false;
        string? failureStage = null;
        Guid? idempotencyKey = null;
        string? filePath = null;
        string? configPath = null;
        Guid? targetId = null;
        Guid? operationId = null;

        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            switch (argument)
            {
                case "-h":
                case "--help":
                    continue;
                case "--json":
                    outputJson = true;
                    continue;
                case "--fail-stage":
                    if (failureStageSpecified)
                    {
                        options = default;
                        error = "Option --fail-stage may only be specified once.";
                        return false;
                    }

                    if (index + 1 >= arguments.Count ||
                        arguments[index + 1].StartsWith('-'))
                    {
                        options = default;
                        error = "Option --fail-stage requires a contract stage value.";
                        return false;
                    }

                    failureStageSpecified = true;
                    failureStage = arguments[++index];
                    continue;
                case "--idempotency-key":
                    if (idempotencyKeySpecified)
                    {
                        options = default;
                        error = "Option --idempotency-key may only be specified once.";
                        return false;
                    }

                    if (index + 1 >= arguments.Count ||
                        arguments[index + 1].StartsWith('-'))
                    {
                        options = default;
                        error = "Option --idempotency-key requires a non-empty GUID.";
                        return false;
                    }

                    idempotencyKeySpecified = true;
                    if (!Guid.TryParse(arguments[++index], out var parsedKey) ||
                        parsedKey == Guid.Empty)
                    {
                        options = default;
                        error = "Option --idempotency-key requires a non-empty GUID.";
                        return false;
                    }

                    idempotencyKey = parsedKey;
                    continue;
                case "--file":
                    if (fileSpecified)
                    {
                        options = default;
                        error = "Option --file may only be specified once.";
                        return false;
                    }

                    if (index + 1 >= arguments.Count ||
                        arguments[index + 1].StartsWith('-'))
                    {
                        options = default;
                        error = "Option --file requires a path.";
                        return false;
                    }

                    fileSpecified = true;
                    filePath = arguments[++index];
                    continue;
                case "--config":
                    if (configSpecified)
                    {
                        options = default;
                        error = "Option --config may only be specified once.";
                        return false;
                    }

                    if (!TryReadOptionValue(
                            arguments,
                            ref index,
                            "--config",
                            out configPath,
                            out error))
                    {
                        options = default;
                        return false;
                    }

                    configSpecified = true;
                    continue;
                case "--target-id":
                    if (targetIdSpecified)
                    {
                        options = default;
                        error = "Option --target-id may only be specified once.";
                        return false;
                    }

                    if (!TryReadGuidOption(
                            arguments,
                            ref index,
                            "--target-id",
                            out targetId,
                            out error))
                    {
                        options = default;
                        return false;
                    }

                    targetIdSpecified = true;
                    continue;
                case "--operation-id":
                    if (operationIdSpecified)
                    {
                        options = default;
                        error = "Option --operation-id may only be specified once.";
                        return false;
                    }

                    if (!TryReadGuidOption(
                            arguments,
                            ref index,
                            "--operation-id",
                            out operationId,
                            out error))
                    {
                        options = default;
                        return false;
                    }

                    operationIdSpecified = true;
                    continue;
                default:
                    positionalArguments.Add(argument);
                    break;
            }
        }

        var command = Command.Health;
        if (positionalArguments.Count > 0)
        {
            switch (positionalArguments[0])
            {
                case "health":
                    if (positionalArguments.Count > 1)
                    {
                        options = default;
                        error = $"Unexpected argument: {positionalArguments[1]}";
                        return false;
                    }

                    break;
                case "simulation":
                    if (positionalArguments.Count < 2)
                    {
                        options = default;
                        error = "Missing simulation command: expected 'latest' or 'start'.";
                        return false;
                    }

                    if (positionalArguments.Count > 2)
                    {
                        options = default;
                        error = $"Unexpected argument: {positionalArguments[2]}";
                        return false;
                    }

                    switch (positionalArguments[1])
                    {
                        case "latest":
                            command = Command.SimulationLatest;
                            break;
                        case "start":
                            command = Command.SimulationStart;
                            break;
                        default:
                            options = default;
                            error =
                                $"Unknown simulation command: {positionalArguments[1]}";
                            return false;
                    }

                    break;
                case "vault":
                    if (positionalArguments.Count < 2)
                    {
                        options = default;
                        error = "Missing vault command: expected 'probe'.";
                        return false;
                    }

                    if (positionalArguments.Count > 2)
                    {
                        options = default;
                        error = $"Unexpected argument: {positionalArguments[2]}";
                        return false;
                    }

                    if (positionalArguments[1] != "probe")
                    {
                        options = default;
                        error = $"Unknown vault command: {positionalArguments[1]}";
                        return false;
                    }

                    command = Command.VaultProbe;
                    break;
                case "credential":
                    if (positionalArguments.Count < 2)
                    {
                        options = default;
                        error =
                            "Missing credential command: expected 'import-ssh-key'.";
                        return false;
                    }

                    if (positionalArguments.Count > 2)
                    {
                        options = default;
                        error = $"Unexpected argument: {positionalArguments[2]}";
                        return false;
                    }

                    if (positionalArguments[1] != "import-ssh-key")
                    {
                        options = default;
                        error =
                            $"Unknown credential command: {positionalArguments[1]}";
                        return false;
                    }

                    command = Command.CredentialImportSshPrivateKey;
                    break;
                case "target":
                    if (positionalArguments.Count != 2)
                    {
                        options = default;
                        error =
                            "Target command expects exactly 'enroll' or 'list'.";
                        return false;
                    }

                    command = positionalArguments[1] switch
                    {
                        "enroll" => Command.TargetEnroll,
                        "list" => Command.TargetList,
                        _ => Command.Invalid,
                    };
                    if (command == Command.Invalid)
                    {
                        options = default;
                        error = $"Unknown target command: {positionalArguments[1]}";
                        return false;
                    }

                    break;
                case "renewal":
                    if (positionalArguments.Count != 2)
                    {
                        options = default;
                        error =
                            "Renewal command expects exactly 'start' or 'get'.";
                        return false;
                    }

                    command = positionalArguments[1] switch
                    {
                        "start" => Command.RenewalStart,
                        "get" => Command.RenewalGet,
                        _ => Command.Invalid,
                    };
                    if (command == Command.Invalid)
                    {
                        options = default;
                        error = $"Unknown renewal command: {positionalArguments[1]}";
                        return false;
                    }

                    break;
                default:
                    options = default;
                    error = $"Unknown command: {positionalArguments[0]}";
                    return false;
            }
        }

        if (failureStageSpecified && command != Command.SimulationStart)
        {
            options = default;
            error = "Option --fail-stage is only valid with 'simulation start'.";
            return false;
        }

        if (idempotencyKeySpecified && command is not
            Command.SimulationStart and not Command.RenewalStart)
        {
            options = default;
            error =
                "Option --idempotency-key is only valid with 'simulation start' or 'renewal start'.";
            return false;
        }

        if (fileSpecified !=
            (command == Command.CredentialImportSshPrivateKey))
        {
            options = default;
            error = command == Command.CredentialImportSshPrivateKey
                ? "Option --file is required with 'credential import-ssh-key'."
                : "Option --file is only valid with 'credential import-ssh-key'.";
            return false;
        }

        if (configSpecified != (command == Command.TargetEnroll))
        {
            options = default;
            error = command == Command.TargetEnroll
                ? "Option --config is required with 'target enroll'."
                : "Option --config is only valid with 'target enroll'.";
            return false;
        }

        if (targetIdSpecified != (command == Command.RenewalStart))
        {
            options = default;
            error = command == Command.RenewalStart
                ? "Option --target-id is required with 'renewal start'."
                : "Option --target-id is only valid with 'renewal start'.";
            return false;
        }

        if (operationIdSpecified != (command == Command.RenewalGet))
        {
            options = default;
            error = command == Command.RenewalGet
                ? "Option --operation-id is required with 'renewal get'."
                : "Option --operation-id is only valid with 'renewal get'.";
            return false;
        }

        if (failureStage is not null &&
            !SimulationContractValues.IsStage(failureStage))
        {
            options = default;
            error =
                $"Unknown contract stage: {failureStage}. Expected one of: {string.Join(", ", SimulationContractValues.Stages)}.";
            return false;
        }

        options = new CommandLineOptions(
            command,
            outputJson,
            failureStage,
            idempotencyKey,
            filePath,
            configPath,
            targetId,
            operationId);
        error = null;
        return true;
    }

    private static bool TryReadOptionValue(
        IReadOnlyList<string> arguments,
        ref int index,
        string optionName,
        out string? value,
        out string? error)
    {
        if (index + 1 >= arguments.Count ||
            arguments[index + 1].StartsWith('-'))
        {
            value = null;
            error = $"Option {optionName} requires a value.";
            return false;
        }

        value = arguments[++index];
        error = null;
        return true;
    }

    private static bool TryReadGuidOption(
        IReadOnlyList<string> arguments,
        ref int index,
        string optionName,
        out Guid? value,
        out string? error)
    {
        if (!TryReadOptionValue(
                arguments,
                ref index,
                optionName,
                out var text,
                out error) ||
            !Guid.TryParseExact(text, "D", out var parsed) ||
            parsed == Guid.Empty)
        {
            value = null;
            error ??= $"Option {optionName} requires a non-empty canonical GUID.";
            return false;
        }

        value = parsed;
        error = null;
        return true;
    }

    private static void WriteHealth(
        TextWriter output,
        HealthSnapshot health,
        bool outputJson)
    {
        if (outputJson)
        {
            output.WriteLine(JsonSerializer.Serialize(health, jsonOptions));
            return;
        }

        output.WriteLine($"CertBaton service: {health.Status}");
        output.WriteLine($"Version: {health.ServiceVersion}");
        output.WriteLine($"Started: {health.StartedAtUtc:O}");
        output.WriteLine($"Responded: {health.RespondedAtUtc:O}");
    }

    private static void WriteSimulationRun(
        TextWriter output,
        SimulationRunSnapshot run,
        bool outputJson)
    {
        if (outputJson)
        {
            output.WriteLine(JsonSerializer.Serialize(run, jsonOptions));
            return;
        }

        output.WriteLine($"Simulation run: {run.RunId:D}");
        output.WriteLine($"Status: {run.Status}");
        output.WriteLine($"Current stage: {FormatOptional(run.CurrentStage)}");
        output.WriteLine($"Terminal stage: {FormatOptional(run.TerminalStage)}");
        output.WriteLine($"Outcome: {FormatOptional(run.Outcome)}");
        output.WriteLine($"Requested: {run.RequestedAtUtc:O}");
        output.WriteLine($"Started: {FormatOptional(run.StartedAtUtc)}");
        output.WriteLine($"Completed: {FormatOptional(run.CompletedAtUtc)}");
        output.WriteLine($"Evidence records: {run.Evidence.Count}");
    }

    private static void WriteVaultProbe(
        TextWriter output,
        VaultProbeSnapshot probe,
        bool outputJson)
    {
        if (outputJson)
        {
            output.WriteLine(JsonSerializer.Serialize(probe, jsonOptions));
            return;
        }

        output.WriteLine($"CertBaton service vault: {probe.Status}");
        output.WriteLine($"Round trip verified: {probe.RoundTripVerified}");
        output.WriteLine($"Temporary record removed: {probe.TemporaryRecordRemoved}");
        output.WriteLine($"Checked: {probe.CheckedAtUtc:O}");
    }

    private static async Task<IpcResponse> ImportSshPrivateKeyAsync(
        string filePath,
        Func<ReadOnlyMemory<byte>, Task<IpcResponse>> importer)
    {
        var fullPath = Path.GetFullPath(filePath);
        var file = new FileInfo(fullPath);
        if (!file.Exists ||
            (file.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                "The SSH private-key path is missing or is a reparse point.");
        }

        if (file.Length is <= 0 or > CredentialContractValues.MaximumSecretBytes)
        {
            throw new IOException(
                $"The SSH private key must contain between 1 and {CredentialContractValues.MaximumSecretBytes} bytes.");
        }

        var privateKey = await File.ReadAllBytesAsync(fullPath)
            .ConfigureAwait(false);
        try
        {
            return await importer(privateKey).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private static async Task<IpcResponse> EnrollTargetAsync(
        string configPath,
        Func<TargetEnrollmentPayload, Task<IpcResponse>> enroll)
    {
        var fullPath = Path.GetFullPath(configPath);
        var file = new FileInfo(fullPath);
        if (!file.Exists ||
            (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
            file.Length is <= 0 or > IpcProtocol.MaximumFrameBytes)
        {
            throw new IOException(
                "The target configuration is missing, is a reparse point, or exceeds the IPC frame limit.");
        }

        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        TargetEnrollmentPayload payload;
        try
        {
            payload = await JsonSerializer.DeserializeAsync<TargetEnrollmentPayload>(
                    stream,
                    inputJsonOptions)
                .ConfigureAwait(false) ??
                throw new InvalidDataException(
                    "The target configuration contains JSON null.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "The target configuration is not valid CertBaton JSON.",
                exception);
        }

        if (!payload.TryValidate(out var validationError))
        {
            throw new InvalidDataException(
                $"The target configuration is invalid: {validationError}");
        }

        return await enroll(payload).ConfigureAwait(false);
    }

    private static void WriteCredentialImport(
        TextWriter output,
        CredentialImportSnapshot credential,
        bool outputJson)
    {
        if (outputJson)
        {
            output.WriteLine(JsonSerializer.Serialize(credential, jsonOptions));
            return;
        }

        output.WriteLine($"Credential reference: {credential.CredentialReference:D}");
        output.WriteLine($"Kind: {credential.Kind}");
        output.WriteLine($"Stored: {credential.StoredAtUtc:O}");
    }

    private static void WriteTarget(
        TextWriter output,
        TargetSnapshot target,
        bool outputJson)
    {
        if (outputJson)
        {
            output.WriteLine(JsonSerializer.Serialize(target, jsonOptions));
            return;
        }

        output.WriteLine($"Target: {target.DisplayName}");
        output.WriteLine($"Target ID: {target.TargetId:D}");
        output.WriteLine($"DNS names: {string.Join(", ", target.DnsNames)}");
        output.WriteLine($"SSH: {target.Username}@{target.Host}:{target.Port}");
        output.WriteLine($"Certificate authority: {target.CertificateAuthority}");
        output.WriteLine($"Automatic renewal: {target.AutoRenew}");
        output.WriteLine($"Status: {target.Status}");
    }

    private static void WriteTargetList(
        TextWriter output,
        TargetListSnapshot targets,
        bool outputJson)
    {
        if (outputJson)
        {
            output.WriteLine(JsonSerializer.Serialize(targets, jsonOptions));
            return;
        }

        if (targets.Targets.Count == 0)
        {
            output.WriteLine("No live targets are enrolled.");
            return;
        }

        foreach (var target in targets.Targets)
        {
            output.WriteLine(
                $"{target.TargetId:D}  {target.Status,-12}  {target.DnsNames[0]}  {target.CertificateAuthority}");
        }
    }

    private static void WriteRenewal(
        TextWriter output,
        RenewalOperationSnapshot operation,
        bool outputJson)
    {
        if (outputJson)
        {
            output.WriteLine(JsonSerializer.Serialize(operation, jsonOptions));
            return;
        }

        output.WriteLine($"Renewal operation: {operation.OperationId:D}");
        output.WriteLine($"Target ID: {operation.TargetId:D}");
        output.WriteLine($"Status: {operation.Status}");
        output.WriteLine($"Requested: {operation.RequestedAtUtc:O}");
        output.WriteLine($"Updated: {operation.UpdatedAtUtc:O}");
        output.WriteLine($"Completed: {FormatOptional(operation.CompletedAtUtc)}");
        output.WriteLine($"Failure: {FormatOptional(operation.FailureCode)}");
        output.WriteLine($"Public TLS verified: {operation.PublicTlsVerified}");
        output.WriteLine(
            $"Challenge cleanup verified: {operation.ChallengeCleanupVerified}");
        output.WriteLine($"Evidence records: {operation.Evidence.Count}");
    }

    private static string FormatOptional(string? value) => value ?? "-";

    private static string FormatOptional(DateTimeOffset? value) =>
        value is null ? "-" : value.Value.ToString("O");

    private static void WriteServiceError(TextWriter error, IpcResponse response)
    {
        error.WriteLine(
            $"CertBaton service error: {response.Error?.Code ?? "unknown"} — {response.Error?.Message ?? "No details were returned."}");
    }

    private static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine(
            """
            CertBaton command-line diagnostics

            Usage:
              certbatonctl health [--json]
              certbatonctl simulation latest [--json]
              certbatonctl simulation start [--fail-stage <contract-stage>] [--idempotency-key <guid>] [--json]
              certbatonctl vault probe [--json]
              certbatonctl credential import-ssh-key --file <path> [--json]
              certbatonctl target enroll --config <non-secret-json> [--json]
              certbatonctl target list [--json]
              certbatonctl renewal start --target-id <guid> [--idempotency-key <guid>] [--json]
              certbatonctl renewal get --operation-id <guid> [--json]
              certbatonctl --help
            """);
    }

    private enum Command
    {
        Health,
        SimulationLatest,
        SimulationStart,
        VaultProbe,
        CredentialImportSshPrivateKey,
        TargetEnroll,
        TargetList,
        RenewalStart,
        RenewalGet,
        Invalid,
    }

    private readonly record struct CommandLineOptions(
        Command Command,
        bool OutputJson,
        string? FailureStage,
        Guid? IdempotencyKey,
        string? FilePath,
        string? ConfigPath,
        Guid? TargetId,
        Guid? OperationId);
}
