using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using CertBaton.Contracts;

namespace CertBaton.Ipc.NamedPipes;

internal static class PipeSecurityFactory
{
    private static readonly SecurityIdentifier ownerRightsSid = new("S-1-3-4");

    private const PipeAccessRights ClientRights =
        PipeAccessRights.ReadData |
        PipeAccessRights.WriteData |
        PipeAccessRights.ReadAttributes |
        PipeAccessRights.WriteAttributes |
        PipeAccessRights.ReadExtendedAttributes |
        PipeAccessRights.WriteExtendedAttributes |
        PipeAccessRights.Synchronize;

    public static PipeSecurity CreateHealthOnlySecurity(
        PipeServerSecurityProfile securityProfile)
    {
        if (securityProfile == PipeServerSecurityProfile.InstalledService)
        {
            return CreateInstalledServiceSecurity(ResolveServiceSid());
        }

        if (securityProfile != PipeServerSecurityProfile.CurrentUserDevelopment)
        {
            throw new ArgumentOutOfRangeException(
                nameof(securityProfile),
                securityProfile,
                "The pipe security profile is not supported.");
        }

        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        AddRule(security, WellKnownSidType.NetworkSid, PipeAccessRights.FullControl, AccessControlType.Deny);
        AddRule(security, WellKnownSidType.AnonymousSid, PipeAccessRights.FullControl, AccessControlType.Deny);

        using var currentIdentity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var currentUser = currentIdentity.User
            ?? throw new InvalidOperationException("The development process does not have a Windows user SID.");

        security.AddAccessRule(
            new PipeAccessRule(
                currentUser,
                PipeAccessRights.FullControl,
                AccessControlType.Allow));
        security.SetOwner(currentUser);

        return security;
    }

    internal static PipeSecurity CreateInstalledServiceSecurityForTest(
        SecurityIdentifier serviceSid) =>
        CreateInstalledServiceSecurity(serviceSid);

    private static PipeSecurity CreateInstalledServiceSecurity(
        SecurityIdentifier serviceSid)
    {
        ArgumentNullException.ThrowIfNull(serviceSid);

        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddRule(security, WellKnownSidType.NetworkSid, PipeAccessRights.FullControl, AccessControlType.Deny);
        AddRule(security, WellKnownSidType.AnonymousSid, PipeAccessRights.FullControl, AccessControlType.Deny);
        ConfigureOwnerRights(security);
        AddRule(security, WellKnownSidType.BuiltinUsersSid, ClientRights, AccessControlType.Allow);
        AddRule(security, WellKnownSidType.BuiltinAdministratorsSid, ClientRights, AccessControlType.Allow);
        security.AddAccessRule(
            new PipeAccessRule(
                serviceSid,
                PipeAccessRights.FullControl,
                AccessControlType.Allow));
        security.SetOwner(serviceSid);
        return security;
    }

    private static SecurityIdentifier ResolveServiceSid()
    {
        var account = new NTAccount("NT SERVICE", IpcProtocol.WindowsServiceName);
        return (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
    }

    private static void ConfigureOwnerRights(PipeSecurity security) =>
        security.AddAccessRule(
            new PipeAccessRule(
                ownerRightsSid,
                PipeAccessRights.ReadPermissions,
                AccessControlType.Allow));

    private static void AddRule(
        PipeSecurity security,
        WellKnownSidType sidType,
        PipeAccessRights rights,
        AccessControlType controlType) =>
        security.AddAccessRule(
            new PipeAccessRule(
                new SecurityIdentifier(sidType, null),
                rights,
                controlType));
}
