using System.Text;

namespace CertBaton.Application.Remote;

public readonly record struct RemotePathSegment
{
    private const int MaximumSegmentBytes = 255;

    public RemotePathSegment(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Validate(value);
        Value = value;
    }

    public string Value { get; }

    public override string ToString() => Value;

    private static void Validate(string value)
    {
        if (value.Length == 0 || value is "." or "..")
        {
            throw new ArgumentException("Remote path segment cannot be empty, '.' or '..'.", nameof(value));
        }

        if (Encoding.UTF8.GetByteCount(value) > MaximumSegmentBytes)
        {
            throw new ArgumentException($"Remote path segment cannot exceed {MaximumSegmentBytes} UTF-8 bytes.", nameof(value));
        }

        foreach (var character in value)
        {
            if (!IsSafeCharacter(character))
            {
                throw new ArgumentException(
                    "Remote path segments may contain only ASCII letters, digits, period, underscore, hyphen, or plus.",
                    nameof(value));
            }
        }
    }

    private static bool IsSafeCharacter(char character) =>
        character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-' or '+';
}

public readonly record struct RemoteTokenSegment
{
    private const int MaximumTokenLength = 256;

    public RemoteTokenSegment(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length is < 1 or > MaximumTokenLength)
        {
            throw new ArgumentException($"Remote token must contain 1 to {MaximumTokenLength} characters.", nameof(value));
        }

        foreach (var character in value)
        {
            if (character is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' or '-'))
            {
                throw new ArgumentException("Remote token must be an unpadded base64url segment.", nameof(value));
            }
        }

        Value = value;
    }

    public string Value { get; }

    public override string ToString() => Value;

    public RemotePathSegment AsPathSegment() => new(Value);
}

public sealed class RemotePosixPath : IEquatable<RemotePosixPath>
{
    private const int MaximumPathBytes = 1024;

    private RemotePosixPath(string value, IReadOnlyList<RemotePathSegment> segments)
    {
        Value = value;
        Segments = segments;
    }

    public string Value { get; }

    public IReadOnlyList<RemotePathSegment> Segments { get; }

    public RemotePathSegment FileName => Segments[^1];

    public RemotePosixPath Parent => Segments.Count == 1
        ? throw new InvalidOperationException("The root directory cannot be represented as a file path.")
        : Create(Segments.Take(Segments.Count - 1));

    public static RemotePosixPath Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (!value.StartsWith('/') || value.EndsWith('/'))
        {
            throw new ArgumentException("Remote path must be an absolute POSIX file path without a trailing slash.", nameof(value));
        }

        if (Encoding.UTF8.GetByteCount(value) > MaximumPathBytes)
        {
            throw new ArgumentException($"Remote path cannot exceed {MaximumPathBytes} UTF-8 bytes.", nameof(value));
        }

        var rawSegments = value[1..].Split('/');
        var segments = rawSegments.Select(segment => new RemotePathSegment(segment)).ToArray();
        return new RemotePosixPath(value, segments);
    }

    public RemotePosixPath Combine(RemotePathSegment segment)
    {
        var combined = $"{Value}/{segment.Value}";
        return Parse(combined);
    }

    public RemotePosixPath Combine(RemoteTokenSegment token) => Combine(token.AsPathSegment());

    public override string ToString() => Value;

    public bool Equals(RemotePosixPath? other) =>
        other is not null && string.Equals(Value, other.Value, StringComparison.Ordinal);

    public override bool Equals(object? obj) => obj is RemotePosixPath other && Equals(other);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    public static bool operator ==(RemotePosixPath? left, RemotePosixPath? right) => Equals(left, right);

    public static bool operator !=(RemotePosixPath? left, RemotePosixPath? right) => !Equals(left, right);

    private static RemotePosixPath Create(IEnumerable<RemotePathSegment> segments)
    {
        var segmentArray = segments.ToArray();
        return new RemotePosixPath('/' + string.Join('/', segmentArray.Select(segment => segment.Value)), segmentArray);
    }
}
