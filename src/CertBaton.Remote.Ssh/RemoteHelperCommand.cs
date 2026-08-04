using CertBaton.Application.Remote;

namespace CertBaton.Remote.Ssh;

internal static class RemoteHelperCommand
{
    private const string HelperInvocation = "sudo -n -- /usr/local/libexec/certbaton/certbaton-helper-v1";

    internal static string Build(RemoteHelperVerbV1 verb, RemoteTransactionId transactionId)
    {
        if (transactionId.Value == Guid.Empty)
        {
            throw new ArgumentException("Remote transaction ID cannot be empty.", nameof(transactionId));
        }

        var verbToken = verb switch
        {
            RemoteHelperVerbV1.Prepare => "prepare",
            RemoteHelperVerbV1.Validate => "validate",
            RemoteHelperVerbV1.Activate => "activate",
            RemoteHelperVerbV1.Verify => "verify",
            RemoteHelperVerbV1.Rollback => "rollback",
            RemoteHelperVerbV1.Commit => "commit",
            RemoteHelperVerbV1.Abort => "abort",
            RemoteHelperVerbV1.Status => "status",
            _ => throw new ArgumentOutOfRangeException(nameof(verb), verb, "Unknown version 1 helper verb."),
        };

        return $"{HelperInvocation} {verbToken} {transactionId}";
    }
}
