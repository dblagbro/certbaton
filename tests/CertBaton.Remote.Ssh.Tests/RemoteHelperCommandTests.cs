using CertBaton.Application.Remote;

namespace CertBaton.Remote.Ssh.Tests;

[TestClass]
public sealed class RemoteHelperCommandTests
{
    private static readonly Guid TransactionGuid = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");

    [TestMethod]
    [DataRow(RemoteHelperVerbV1.Prepare, "prepare")]
    [DataRow(RemoteHelperVerbV1.Validate, "validate")]
    [DataRow(RemoteHelperVerbV1.Activate, "activate")]
    [DataRow(RemoteHelperVerbV1.Verify, "verify")]
    [DataRow(RemoteHelperVerbV1.Rollback, "rollback")]
    [DataRow(RemoteHelperVerbV1.Commit, "commit")]
    [DataRow(RemoteHelperVerbV1.Abort, "abort")]
    [DataRow(RemoteHelperVerbV1.Status, "status")]
    public void BuildMapsOnlyVersionedEnumAndCanonicalUuid(RemoteHelperVerbV1 verb, string expectedVerb)
    {
        var transactionId = new RemoteTransactionId(TransactionGuid);

        var command = RemoteHelperCommand.Build(verb, transactionId);

        Assert.AreEqual(
            $"sudo -n -- /usr/local/libexec/certbaton/certbaton-helper-v1 {expectedVerb} 01234567-89ab-cdef-0123-456789abcdef",
            command);
    }

    [TestMethod]
    public void BuildRejectsUnknownVerbAndDefaultTransactionId()
    {
        var transactionId = new RemoteTransactionId(TransactionGuid);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            RemoteHelperCommand.Build((RemoteHelperVerbV1)999, transactionId));
        Assert.Throws<ArgumentException>(() =>
            RemoteHelperCommand.Build(RemoteHelperVerbV1.Status, default));
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("0123456789abcdef0123456789abcdef")]
    [DataRow("{01234567-89ab-cdef-0123-456789abcdef}")]
    [DataRow("01234567-89ab-cdef-0123-456789abcde;")]
    public void TransactionIdParseRejectsNonCanonicalInput(string value)
    {
        Assert.Throws<FormatException>(() => RemoteTransactionId.Parse(value));
    }

    [TestMethod]
    public void TransactionIdRejectsEmptyGuid()
    {
        Assert.Throws<ArgumentException>(() => new RemoteTransactionId(Guid.Empty));
    }
}
