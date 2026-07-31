using System.Text.Json;
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

    private static Task<int> Main(string[] arguments) =>
        RunAsync(arguments, Console.Out, Console.Error);

    internal static async Task<int> RunAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<Task<IpcResponse>>? getHealthAsync = null,
        Func<Task<IpcResponse>>? getLatestSimulationAsync = null,
        Func<Guid, string?, Task<IpcResponse>>? startSimulationAsync = null)
    {
        var unknownSwitch = arguments.FirstOrDefault(
            static argument =>
                argument.StartsWith('-') &&
                argument is not "-h" and
                not "--help" and
                not "--json" and
                not "--fail-stage" and
                not "--idempotency-key");
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
            else
            {
                var simulationRun = response.Result?.SimulationRun;
                if (simulationRun is null)
                {
                    WriteServiceError(error, response);
                    return 1;
                }

                WriteSimulationRun(output, simulationRun, options.OutputJson);
            }

            return 0;
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
        string? failureStage = null;
        Guid? idempotencyKey = null;

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

        if (idempotencyKeySpecified && command != Command.SimulationStart)
        {
            options = default;
            error =
                "Option --idempotency-key is only valid with 'simulation start'.";
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
            idempotencyKey);
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
              certbatonctl --help
            """);
    }

    private enum Command
    {
        Health,
        SimulationLatest,
        SimulationStart,
    }

    private readonly record struct CommandLineOptions(
        Command Command,
        bool OutputJson,
        string? FailureStage,
        Guid? IdempotencyKey);
}
