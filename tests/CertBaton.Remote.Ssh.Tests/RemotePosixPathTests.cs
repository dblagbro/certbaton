using CertBaton.Application.Remote;

namespace CertBaton.Remote.Ssh.Tests;

[TestClass]
public sealed class RemotePosixPathTests
{
    [TestMethod]
    public void ParseAndCombineBuildsCanonicalChallengePath()
    {
        var challengeDirectory = RemotePosixPath.Parse("/var/www/site/.well-known/acme-challenge");
        var token = new RemoteTokenSegment("abc_DEF-123");

        var challengeFile = challengeDirectory.Combine(token);

        Assert.AreEqual("/var/www/site/.well-known/acme-challenge/abc_DEF-123", challengeFile.Value);
        Assert.AreEqual("abc_DEF-123", challengeFile.FileName.Value);
        Assert.AreEqual(challengeDirectory, challengeFile.Parent);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("relative/path")]
    [DataRow("/trailing/")]
    [DataRow("/double//slash")]
    [DataRow("/dot/./file")]
    [DataRow("/traversal/../file")]
    [DataRow("/shell/$(id)")]
    [DataRow("/line/break\nfile")]
    [DataRow("/back\\slash")]
    public void ParseRejectsNonCanonicalOrUnsafePath(string path)
    {
        Assert.Throws<ArgumentException>(() => RemotePosixPath.Parse(path));
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("abc=")]
    [DataRow("abc.def")]
    [DataRow("abc/def")]
    [DataRow("$(id)")]
    [DataRow("abc\ndef")]
    public void TokenRejectsAnythingOutsideBase64UrlAlphabet(string token)
    {
        Assert.Throws<ArgumentException>(() => new RemoteTokenSegment(token));
    }

    [TestMethod]
    public void ParseRejectsOverlongSegment()
    {
        var path = "/" + new string('a', 256);

        Assert.Throws<ArgumentException>(() => RemotePosixPath.Parse(path));
    }
}
