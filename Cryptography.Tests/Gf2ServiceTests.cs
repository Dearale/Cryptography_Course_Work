using Cryptography.Core;

namespace Cryptography.Tests;

public class Gf2ServiceTests
{
    [TestCase(0x57, 0x83, 0x1B, 0xC1)]
    [TestCase(0x80, 0x02, 0x65, 0x65)]
    [TestCase(0xFF, 0x00, 0x65, 0x00)]
    [TestCase(0xFF, 0x01, 0x65, 0xFF)]
    [TestCase(0x00, 0xFF, 0x65, 0x00)]
    public void MultiplyMatchesKnownResults(int a, int b, int mod, int expected)
    {
        Gf2Service gf = new Gf2Service();
        byte res = gf.MultiplyUnchecked((byte)a, (byte)b, (byte)mod);
        Assert.That(res, Is.EqualTo((byte)expected));
    }
}
