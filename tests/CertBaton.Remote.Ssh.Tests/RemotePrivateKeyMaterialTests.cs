using CertBaton.Application.Remote;

namespace CertBaton.Remote.Ssh.Tests;

[TestClass]
public sealed class RemotePrivateKeyMaterialTests
{
    [TestMethod]
    public void ConstructorCopiesCallerBufferAndOpenReadStreamStaysInMemory()
    {
        byte[] source = [1, 2, 3, 4];
        using var material = new RemotePrivateKeyMaterial(source);
        source[0] = 99;

        using var stream = material.OpenReadStream();
        using var destination = new MemoryStream();
        stream.CopyTo(destination);

        CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4 }, destination.ToArray());
    }

    [TestMethod]
    public void DisposeMakesMaterialUnavailable()
    {
        var material = new RemotePrivateKeyMaterial([1, 2, 3, 4]);

        material.Dispose();

        Assert.Throws<ObjectDisposedException>(() => material.OpenReadStream());
        Assert.Throws<ObjectDisposedException>(() => _ = material.Length);
    }

    [TestMethod]
    public void ConstructorRejectsEmptyOrOversizedKey()
    {
        Assert.Throws<ArgumentException>(() => new RemotePrivateKeyMaterial([]));
        Assert.Throws<ArgumentException>(() =>
            new RemotePrivateKeyMaterial(new byte[RemotePrivateKeyMaterial.MaximumPrivateKeyBytes + 1]));
    }
}
