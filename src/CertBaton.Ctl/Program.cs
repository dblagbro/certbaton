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
        Func<Task<IpcResponse>>? getHealthAsync = null)
    {
        var unknownSwitch = arguments.FirstOrDefault(
            static argument =>
                argument.StartsWith('-') &&
                argument is not "-h" and not "--help" and not "--json");
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

        var positionalArguments = arguments
            .Where(static argument => !argument.StartsWith('-'))
            .ToArray();
        var command = positionalArguments.FirstOrDefault() ?? "health";
        if (positionalArguments.Length > 1)
        {
            error.WriteLine($"Unexpected argument: {positionalArguments[1]}");
            PrintUsage(error);
            return 2;
        }

        if (!string.Equals(command, "health", StringComparison.Ordinal))
        {
            error.WriteLine($"Unknown command: {command}");
            PrintUsage(error);
            return 2;
        }

        var outputJson = arguments.Contains("--json", StringComparer.Ordinal);

        try
        {
            if (getHealthAsync is null)
            {
                var client = new CertBatonPipeClient();
                getHealthAsync = () => client.GetHealthAsync();
            }

            var response = await getHealthAsync().ConfigureAwait(false);

            if (!response.Success || response.Result is null)
            {
                error.WriteLine(
                    $"CertBaton service error: {response.Error?.Code ?? "unknown"} — {response.Error?.Message ?? "No details were returned."}");
                return 1;
            }

            if (outputJson)
            {
                output.WriteLine(
                    JsonSerializer.Serialize(
                        response.Result,
                        jsonOptions));
            }
            else
            {
                output.WriteLine($"CertBaton service: {response.Result.Status}");
                output.WriteLine($"Version: {response.Result.ServiceVersion}");
                output.WriteLine($"Started: {response.Result.StartedAtUtc:O}");
                output.WriteLine($"Responded: {response.Result.RespondedAtUtc:O}");
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

    private static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine(
            """
            CertBaton command-line diagnostics

            Usage:
              certbatonctl health [--json]
              certbatonctl --help
            """);
    }
}
