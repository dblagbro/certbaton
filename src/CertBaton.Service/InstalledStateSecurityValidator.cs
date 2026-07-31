using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CertBaton.Service;

internal static class InstalledStateSecurityValidator
{
    internal const string ServiceSidValue =
        "S-1-5-80-2998542184-680993539-724725283-631637665-607464993";

    private const string PathPolicyFailureMessage =
        "The protected CertBaton state path is not a local, fixed NTFS directory path. " +
        "Repair the installation before starting the service.";

    private const string AccessPolicyFailureMessage =
        "The protected CertBaton state directory owner or access rules do not match " +
        "the installed security policy. Repair the installation before starting the service.";

    private static readonly SecurityIdentifier LocalSystemSid =
        new(WellKnownSidType.LocalSystemSid, domainSid: null);

    private static readonly SecurityIdentifier BuiltinAdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, domainSid: null);

    private static readonly SecurityIdentifier ServiceSid = new(ServiceSidValue);

    private static readonly InheritanceFlags RequiredInheritance =
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    private static readonly FileSystemRights RequiredServiceRights =
        FileSystemRights.Modify | FileSystemRights.Synchronize;

    internal static void Validate(string stateDirectory)
    {
        try
        {
            Validate(
                stateDirectory,
                File.GetAttributes,
                path => new DirectoryInfo(path).GetAccessControl(
                    AccessControlSections.Owner | AccessControlSections.Access),
                GetVolumeInfo);
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (Exception exception)
            when (exception is IOException
                or UnauthorizedAccessException
                or SecurityException)
        {
            throw new InvalidOperationException(PathPolicyFailureMessage);
        }
    }

    internal static void Validate(
        string stateDirectory,
        Func<string, FileAttributes> getAttributes,
        Func<string, DirectorySecurity> getAccessControl,
        Func<string, StateVolumeInfo> getVolumeInfo)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stateDirectory);
        ArgumentNullException.ThrowIfNull(getAttributes);
        ArgumentNullException.ThrowIfNull(getAccessControl);
        ArgumentNullException.ThrowIfNull(getVolumeInfo);

        if (!Path.IsPathFullyQualified(stateDirectory))
        {
            throw new InvalidOperationException(PathPolicyFailureMessage);
        }

        var fullPath = Path.GetFullPath(stateDirectory);
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root)
            || root.StartsWith(@"\\", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(PathPolicyFailureMessage);
        }

        var volumeInfo = getVolumeInfo(root);
        if (volumeInfo.DriveType != DriveType.Fixed
            || !string.Equals(
                volumeInfo.DriveFormat,
                "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(PathPolicyFailureMessage);
        }

        for (DirectoryInfo? directory = new(fullPath);
             directory is not null;
             directory = directory.Parent)
        {
            var attributes = getAttributes(directory.FullName);
            if ((attributes & FileAttributes.Directory) == 0
                || (attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException(PathPolicyFailureMessage);
            }
        }

        ValidateAccessControl(getAccessControl(fullPath));
    }

    internal static void ValidateAccessControl(DirectorySecurity accessControl)
    {
        ArgumentNullException.ThrowIfNull(accessControl);

        if (!accessControl.AreAccessRulesProtected
            || accessControl.GetOwner(typeof(SecurityIdentifier))
                is not SecurityIdentifier owner
            || !owner.Equals(LocalSystemSid))
        {
            throw new InvalidOperationException(AccessPolicyFailureMessage);
        }

        var grantedRights = new Dictionary<string, FileSystemRights>(
            StringComparer.Ordinal);
        var rules = accessControl.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));

        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.IdentityReference is not SecurityIdentifier identity
                || rule.IsInherited
                || rule.AccessControlType != AccessControlType.Allow
                || rule.InheritanceFlags != RequiredInheritance
                || rule.PropagationFlags != PropagationFlags.None
                || !IsAllowedIdentity(identity))
            {
                throw new InvalidOperationException(AccessPolicyFailureMessage);
            }

            grantedRights.TryGetValue(identity.Value, out var currentRights);
            grantedRights[identity.Value] = currentRights | rule.FileSystemRights;
        }

        if (grantedRights.Count != 3
            || !HasExactRights(
                grantedRights,
                LocalSystemSid,
                FileSystemRights.FullControl)
            || !HasExactRights(
                grantedRights,
                BuiltinAdministratorsSid,
                FileSystemRights.FullControl)
            || !HasExactRights(
                grantedRights,
                ServiceSid,
                RequiredServiceRights))
        {
            throw new InvalidOperationException(AccessPolicyFailureMessage);
        }
    }

    private static bool IsAllowedIdentity(SecurityIdentifier identity) =>
        identity.Equals(LocalSystemSid)
        || identity.Equals(BuiltinAdministratorsSid)
        || identity.Equals(ServiceSid);

    private static StateVolumeInfo GetVolumeInfo(string root)
    {
        var drive = new DriveInfo(root);
        return new StateVolumeInfo(drive.DriveType, drive.DriveFormat);
    }

    private static bool HasExactRights(
        Dictionary<string, FileSystemRights> grantedRights,
        SecurityIdentifier identity,
        FileSystemRights expectedRights) =>
        grantedRights.TryGetValue(identity.Value, out var actualRights)
        && actualRights == expectedRights;

    internal readonly record struct StateVolumeInfo(
        DriveType DriveType,
        string DriveFormat);
}
