using System.Security.AccessControl;
using System.Security.Principal;
using CertBaton.Service;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class InstalledStateSecurityValidatorTests
{
    private static readonly SecurityIdentifier LocalSystemSid =
        new(WellKnownSidType.LocalSystemSid, domainSid: null);

    private static readonly SecurityIdentifier BuiltinAdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, domainSid: null);

    private static readonly SecurityIdentifier ServiceSid =
        new(InstalledStateSecurityValidator.ServiceSidValue);

    private static readonly InheritanceFlags DirectoryAndChildren =
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    [TestMethod]
    public void ExpectedProtectedDescriptorIsAccepted()
    {
        InstalledStateSecurityValidator.ValidateAccessControl(
            CreateExpectedAccessControl());
    }

    [TestMethod]
    public void DescriptorWithWrongOwnerIsRejected()
    {
        var accessControl = CreateExpectedAccessControl();
        accessControl.SetOwner(BuiltinAdministratorsSid);

        Assert.ThrowsExactly<InvalidOperationException>(
            () => InstalledStateSecurityValidator.ValidateAccessControl(
                accessControl));
    }

    [TestMethod]
    public void DescriptorWithInheritedDaclIsRejected()
    {
        var accessControl = CreateExpectedAccessControl();
        accessControl.SetAccessRuleProtection(
            isProtected: false,
            preserveInheritance: true);

        Assert.ThrowsExactly<InvalidOperationException>(
            () => InstalledStateSecurityValidator.ValidateAccessControl(
                accessControl));
    }

    [TestMethod]
    public void DescriptorWithOrdinaryUsersRuleIsRejected()
    {
        var accessControl = CreateExpectedAccessControl();
        accessControl.AddAccessRule(CreateRule(
            new SecurityIdentifier(
                WellKnownSidType.BuiltinUsersSid,
                domainSid: null),
            FileSystemRights.ReadAndExecute));

        Assert.ThrowsExactly<InvalidOperationException>(
            () => InstalledStateSecurityValidator.ValidateAccessControl(
                accessControl));
    }

    [TestMethod]
    public void DescriptorGivingServiceAclOwnershipRightsIsRejected()
    {
        var accessControl = CreateExpectedAccessControl();
        accessControl.SetAccessRule(CreateRule(
            ServiceSid,
            FileSystemRights.FullControl));

        Assert.ThrowsExactly<InvalidOperationException>(
            () => InstalledStateSecurityValidator.ValidateAccessControl(
                accessControl));
    }

    [TestMethod]
    public void DescriptorWithoutServiceChildInheritanceIsRejected()
    {
        var accessControl = CreateExpectedAccessControl();
        accessControl.RemoveAccessRuleAll(CreateRule(
            ServiceSid,
            FileSystemRights.Modify));
        accessControl.AddAccessRule(new FileSystemAccessRule(
            ServiceSid,
            FileSystemRights.Modify,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));

        Assert.ThrowsExactly<InvalidOperationException>(
            () => InstalledStateSecurityValidator.ValidateAccessControl(
                accessControl));
    }

    [TestMethod]
    public void AncestorReparsePointIsRejectedBeforeAclIsRead()
    {
        var statePath = Path.Combine(
            Path.GetPathRoot(Environment.SystemDirectory)!,
            "ProgramData",
            "CertBaton",
            "State");
        var reparsePath = Directory.GetParent(statePath)!.FullName;
        var aclWasRead = false;

        Assert.ThrowsExactly<InvalidOperationException>(
            () => InstalledStateSecurityValidator.Validate(
                statePath,
                path => FileAttributes.Directory
                    | (string.Equals(
                        path,
                        reparsePath,
                        StringComparison.OrdinalIgnoreCase)
                        ? FileAttributes.ReparsePoint
                        : 0),
                _ =>
                {
                    aclWasRead = true;
                    return CreateExpectedAccessControl();
                },
                _ => FixedNtfsVolume()));

        Assert.IsFalse(aclWasRead);
    }

    [TestMethod]
    public void LocalFixedNtfsPathWithExpectedAclIsAccepted()
    {
        InstalledStateSecurityValidator.Validate(
            LocalStatePath(),
            _ => FileAttributes.Directory,
            _ => CreateExpectedAccessControl(),
            _ => new InstalledStateSecurityValidator.StateVolumeInfo(
                DriveType.Fixed,
                "ntfs"));
    }

    [TestMethod]
    public void NonFixedVolumeIsRejectedBeforeFilesystemAccess()
    {
        var filesystemWasRead = false;

        Assert.ThrowsExactly<InvalidOperationException>(
            () => InstalledStateSecurityValidator.Validate(
                LocalStatePath(),
                _ =>
                {
                    filesystemWasRead = true;
                    return FileAttributes.Directory;
                },
                _ =>
                {
                    filesystemWasRead = true;
                    return CreateExpectedAccessControl();
                },
                _ => new InstalledStateSecurityValidator.StateVolumeInfo(
                    DriveType.Removable,
                    "NTFS")));

        Assert.IsFalse(filesystemWasRead);
    }

    [TestMethod]
    public void NonNtfsVolumeIsRejectedBeforeFilesystemAccess()
    {
        var filesystemWasRead = false;

        Assert.ThrowsExactly<InvalidOperationException>(
            () => InstalledStateSecurityValidator.Validate(
                LocalStatePath(),
                _ =>
                {
                    filesystemWasRead = true;
                    return FileAttributes.Directory;
                },
                _ =>
                {
                    filesystemWasRead = true;
                    return CreateExpectedAccessControl();
                },
                _ => new InstalledStateSecurityValidator.StateVolumeInfo(
                    DriveType.Fixed,
                    "ReFS")));

        Assert.IsFalse(filesystemWasRead);
    }

    [TestMethod]
    public void UncStatePathIsRejectedBeforeFilesystemAccess()
    {
        var filesystemWasRead = false;

        Assert.ThrowsExactly<InvalidOperationException>(
            () => InstalledStateSecurityValidator.Validate(
                @"\\server\share\CertBaton\State",
                _ =>
                {
                    filesystemWasRead = true;
                    return FileAttributes.Directory;
                },
                _ =>
                {
                    filesystemWasRead = true;
                    return CreateExpectedAccessControl();
                },
                _ =>
                {
                    filesystemWasRead = true;
                    return FixedNtfsVolume();
                }));

        Assert.IsFalse(filesystemWasRead);
    }

    private static DirectorySecurity CreateExpectedAccessControl()
    {
        var accessControl = new DirectorySecurity();
        accessControl.SetOwner(LocalSystemSid);
        accessControl.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        accessControl.AddAccessRule(CreateRule(
            LocalSystemSid,
            FileSystemRights.FullControl));
        accessControl.AddAccessRule(CreateRule(
            BuiltinAdministratorsSid,
            FileSystemRights.FullControl));
        accessControl.AddAccessRule(CreateRule(
            ServiceSid,
            FileSystemRights.Modify));
        return accessControl;
    }

    private static string LocalStatePath() =>
        Path.Combine(
            Path.GetPathRoot(Environment.SystemDirectory)!,
            "ProgramData",
            "CertBaton",
            "State");

    private static InstalledStateSecurityValidator.StateVolumeInfo
        FixedNtfsVolume() =>
        new(DriveType.Fixed, "NTFS");

    private static FileSystemAccessRule CreateRule(
        SecurityIdentifier identity,
        FileSystemRights rights) =>
        new(
            identity,
            rights,
            DirectoryAndChildren,
            PropagationFlags.None,
            AccessControlType.Allow);
}
