using System.Security.Principal;

namespace CertBaton.Ipc.NamedPipes;

public sealed record PipeClientIdentity(
    string UserSid,
    bool IsAdministrator,
    TokenImpersonationLevel ImpersonationLevel);

internal static class PipeClientIdentityReader
{
    public static PipeClientIdentity Read(System.IO.Pipes.NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);

        PipeClientIdentity? result = null;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            var userSid = identity.User
                ?? throw new UnauthorizedAccessException("The pipe client did not have a Windows user SID.");

            if (identity.IsAnonymous)
            {
                throw new UnauthorizedAccessException("Anonymous pipe clients are not permitted.");
            }

            var principal = new WindowsPrincipal(identity);
            var isAdministrator = principal.IsInRole(WindowsBuiltInRole.Administrator);
            result = new PipeClientIdentity(
                userSid.Value,
                isAdministrator,
                identity.ImpersonationLevel);
        });

        return result
            ?? throw new UnauthorizedAccessException("The pipe client identity could not be established.");
    }
}
