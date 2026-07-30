using System.Buffers.Binary;
using System.Text;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class IpcFrameCodecTests
{
    [TestMethod]
    public async Task RoundTripPreservesProtocolMessage()
    {
        var expected = IpcRequest.CreateHealth(TimeProvider.System);
        var codec = new IpcFrameCodec();
        await using var stream = new MemoryStream();

        await codec.WriteAsync(stream, expected);
        stream.Position = 0;
        var actual = await codec.ReadAsync<IpcRequest>(stream);

        Assert.AreEqual(expected, actual);
    }

    [TestMethod]
    public async Task ReadAsyncRejectsFrameLargerThanLimit()
    {
        const int maximumBytes = 32;
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, maximumBytes + 1);
        var codec = new IpcFrameCodec(maximumBytes);
        await using var stream = new MemoryStream(header);

        await Assert.ThrowsExactlyAsync<IpcProtocolException>(
            async () => await codec.ReadAsync<IpcRequest>(stream));
    }

    [TestMethod]
    public async Task ReadAsyncRejectsUnknownJsonMembers()
    {
        const string invalidJson = """
            {
              "protocolVersion": 1,
              "requestId": "0f6facb7-1a14-4a29-bf0c-40fd8dc277fa",
              "method": "health",
              "sentAtUtc": "2026-07-29T00:00:00Z",
              "deadlineUtc": "2026-07-29T00:00:03Z",
              "unexpected": true
            }
            """;

        var payload = Encoding.UTF8.GetBytes(invalidJson);
        var frame = new byte[sizeof(int) + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, payload.Length);
        payload.CopyTo(frame.AsSpan(sizeof(int)));

        var codec = new IpcFrameCodec();
        await using var stream = new MemoryStream(frame);

        await Assert.ThrowsExactlyAsync<IpcProtocolException>(
            async () => await codec.ReadAsync<IpcRequest>(stream));
    }

    [TestMethod]
    public async Task ReadAsyncRejectsDuplicateJsonMembers()
    {
        const string invalidJson = """
            {
              "protocolVersion": 1,
              "protocolVersion": 1,
              "requestId": "0f6facb7-1a14-4a29-bf0c-40fd8dc277fa",
              "method": "health",
              "sentAtUtc": "2026-07-29T00:00:00Z",
              "deadlineUtc": "2026-07-29T00:00:03Z"
            }
            """;

        var payload = Encoding.UTF8.GetBytes(invalidJson);
        var frame = new byte[sizeof(int) + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, payload.Length);
        payload.CopyTo(frame.AsSpan(sizeof(int)));

        var codec = new IpcFrameCodec();
        await using var stream = new MemoryStream(frame);

        await Assert.ThrowsExactlyAsync<IpcProtocolException>(
            async () => await codec.ReadAsync<IpcRequest>(stream));
    }
}
