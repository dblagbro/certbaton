using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using CertBaton.Contracts;

namespace CertBaton.Ipc.NamedPipes;

public sealed class IpcFrameCodec
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 32,
        PropertyNameCaseInsensitive = false,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private readonly int maximumFrameBytes;

    public IpcFrameCodec(int maximumFrameBytes = IpcProtocol.MaximumFrameBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumFrameBytes);
        this.maximumFrameBytes = maximumFrameBytes;
    }

    public async ValueTask WriteAsync<T>(
        Stream stream,
        T value,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(value);

        var payload = JsonSerializer.SerializeToUtf8Bytes(value, SerializerOptions);
        if (payload.Length > maximumFrameBytes)
        {
            throw new IpcProtocolException(
                $"The encoded IPC frame is {payload.Length} bytes; the limit is {maximumFrameBytes} bytes.");
        }

        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);

        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<T> ReadAsync<T>(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (payloadLength <= 0 || payloadLength > maximumFrameBytes)
        {
            throw new IpcProtocolException(
                $"The IPC frame length {payloadLength} is outside the allowed range of 1 to {maximumFrameBytes} bytes.");
        }

        var payload = new byte[payloadLength];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);

        try
        {
            using var document = JsonDocument.Parse(
                payload,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = SerializerOptions.MaxDepth,
                });
            ValidateNoDuplicateProperties(document.RootElement);

            return JsonSerializer.Deserialize<T>(payload, SerializerOptions)
                ?? throw new IpcProtocolException("The IPC frame contained a JSON null value.");
        }
        catch (JsonException exception)
        {
            throw new IpcProtocolException("The IPC frame did not contain a valid protocol message.", exception);
        }
    }

    private static void ValidateNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new IpcProtocolException(
                        $"The IPC frame contained a duplicate JSON property named '{property.Name}'.");
                }

                ValidateNoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                ValidateNoDuplicateProperties(item);
            }
        }
    }
}
