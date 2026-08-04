using Certify.ACME.Anvil.Acme;

namespace CertBaton.Acme.Tests;

internal sealed class ScriptedAcmeHttpClient : IAcmeHttpClient
{
    private static readonly ILookup<string, Uri> noLinks =
        Array.Empty<KeyValuePair<string, Uri>>()
            .ToLookup(static pair => pair.Key, static pair => pair.Value);
    private readonly Queue<Step> steps = new();
    private int nonceSequence;

    public void EnqueueGet<T>(
        Uri uri,
        T resource,
        Uri? location = null,
        AcmeError? error = null,
        int retryAfter = 0) =>
        steps.Enqueue(new Step(
            "GET",
            uri,
            typeof(T),
            resource,
            location,
            error,
            retryAfter));

    public void EnqueuePost<T>(
        Uri uri,
        T resource,
        Uri? location = null,
        AcmeError? error = null,
        int retryAfter = 0) =>
        steps.Enqueue(new Step(
            "POST",
            uri,
            typeof(T),
            resource,
            location,
            error,
            retryAfter));

    public Task<string> ConsumeNonce() =>
        Task.FromResult($"test-nonce-{Interlocked.Increment(ref nonceSequence)}");

    public Task<AcmeHttpResponse<T>> Post<T>(Uri uri, object payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return Task.FromResult(Take<T>("POST", uri));
    }

    public Task<AcmeHttpResponse<T>> Get<T>(Uri uri) =>
        Task.FromResult(Take<T>("GET", uri));

    public void AssertComplete() =>
        Assert.AreEqual(0, steps.Count, "All scripted ACME HTTP calls should be consumed.");

    private AcmeHttpResponse<T> Take<T>(string method, Uri uri)
    {
        if (!steps.TryDequeue(out var step))
        {
            throw new InvalidOperationException(
                $"Unexpected {method} {uri} returning {typeof(T).FullName}.");
        }

        Assert.AreEqual(step.Method, method);
        Assert.AreEqual(step.Uri, uri);
        Assert.AreEqual(typeof(T), step.ResourceType);

        return new AcmeHttpResponse<T>(
            step.Location ?? uri,
            (T)step.Resource!,
            noLinks,
            step.Error,
            step.RetryAfter);
    }

    private sealed record Step(
        string Method,
        Uri Uri,
        Type ResourceType,
        object? Resource,
        Uri? Location,
        AcmeError? Error,
        int RetryAfter);
}
