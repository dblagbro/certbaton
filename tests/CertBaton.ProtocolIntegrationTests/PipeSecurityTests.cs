using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using CertBaton.Ipc.NamedPipes;

namespace CertBaton.ProtocolIntegrationTests;

[TestClass]
public sealed class PipeSecurityTests
{
    [TestMethod]
    public void InstalledProfileUsesExactServiceOwnerAndRestrictsImplicitOwnerRights()
    {
        var serviceSid = new SecurityIdentifier("S-1-5-80-1-2-3-4-5");
        var security = PipeSecurityFactory.CreateInstalledServiceSecurityForTest(serviceSid);

        Assert.AreEqual(
            serviceSid,
            security.GetOwner(typeof(SecurityIdentifier)));

        var rules = security
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .ToArray();

        Assert.IsTrue(
            rules.Any(
                rule =>
                    Equals(rule.IdentityReference, serviceSid) &&
                    rule.AccessControlType == AccessControlType.Allow &&
                    rule.PipeAccessRights.HasFlag(PipeAccessRights.FullControl)));

        var ownerRightsSid = new SecurityIdentifier("S-1-3-4");
        var ownerRightsRule = rules.Single(
            rule => Equals(rule.IdentityReference, ownerRightsSid));

        Assert.AreEqual(AccessControlType.Allow, ownerRightsRule.AccessControlType);
        Assert.IsTrue(
            ownerRightsRule.PipeAccessRights.HasFlag(PipeAccessRights.ReadPermissions));
        Assert.IsFalse(
            ownerRightsRule.PipeAccessRights.HasFlag(PipeAccessRights.ChangePermissions));

        var localServiceSid = new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null);
        Assert.IsFalse(
            rules.Any(
                rule =>
                    Equals(rule.IdentityReference, localServiceSid) &&
                    rule.AccessControlType == AccessControlType.Allow));
    }
}
