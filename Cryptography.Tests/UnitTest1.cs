using Cryptography.Core;
using NUnit.Framework;

namespace Cryptography.Tests;

public class Rc6Tests
{
    [TestCase(16, "8FC3A53656B1F778C129DF4E9848A41E")]
    [TestCase(24, "6CD61BCB190B30384E8A3F168690AE82")]
    [TestCase(32, "8F5FBD0510D15FA893FA3FDA6E857EC2")]
    public void ZeroVectorMatchesSpecification(int keyLen, string expectedHex)
    {
        Rc6 cipher = new Rc6();
        cipher.SetKey(new byte[keyLen]);

        byte[] data = new byte[16];
        byte[] expected = Convert.FromHexString(expectedHex);

        Assert.That(cipher.Encrypt(data), Is.EqualTo(expected));
        Assert.That(cipher.Decrypt(expected), Is.EqualTo(data));
    }

    [Test]
    public void NonZeroVectorMatchesPublishedResult()
    {
        Rc6 cipher = new Rc6();
        byte[] key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        byte[] data = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        byte[] expected = Convert.FromHexString("3A96F9C7F6755CFE46F00E3DCD5D2A3C");

        cipher.SetKey(key);

        Assert.That(cipher.Encrypt(data), Is.EqualTo(expected));
        Assert.That(cipher.Decrypt(expected), Is.EqualTo(data));
    }

    [Test]
    public void InvalidInputIsRejected()
    {
        Rc6 cipher = new Rc6();

        Assert.Throws<InvalidOperationException>(
            () => cipher.Encrypt(new byte[16]));

        Assert.Throws<ArgumentException>(
            () => cipher.SetKey(new byte[15]));

        cipher.SetKey(new byte[16]);

        Assert.Throws<ArgumentException>(
            () => cipher.Encrypt(new byte[15]));

        Assert.Throws<ArgumentException>(
            () => cipher.Decrypt(new byte[17]));
    }
}
