using Cryptography.Core;
using Aes = System.Security.Cryptography.Aes;
using CryptographicException = System.Security.Cryptography.CryptographicException;
using SystemPadding = System.Security.Cryptography.PaddingMode;

namespace Cryptography.Tests;

public class BlockPaddingTests
{
    [TestCase(PaddingMode.Zeros, "", "")]
    [TestCase(PaddingMode.Zeros, "010203", "0102030000000000")]
    [TestCase(PaddingMode.Zeros, "0102030405060708", "0102030405060708")]
    [TestCase(PaddingMode.AnsiX923, "", "0000000000000008")]
    [TestCase(PaddingMode.AnsiX923, "010203", "0102030000000005")]
    [TestCase(PaddingMode.AnsiX923, "0102030405060708", "01020304050607080000000000000008")]
    [TestCase(PaddingMode.PKCS7, "", "0808080808080808")]
    [TestCase(PaddingMode.PKCS7, "010203", "0102030505050505")]
    [TestCase(PaddingMode.PKCS7, "0102030405060708", "01020304050607080808080808080808")]
    public void MatchesExpectedBytes(PaddingMode padding, string plainHex, string paddedHex)
    {
        byte[] plain = Convert.FromHexString(plainHex);
        byte[] padded = Convert.FromHexString(paddedHex);
        Assert.That(BlockPadding.Apply(plain, 8, padding), Is.EqualTo(padded));
        Assert.That(BlockPadding.Remove(padded, 8, padding, plain.Length), Is.EqualTo(plain));
    }

    [Test]
    public void MatchesPlatformPadding(
        [Values(PaddingMode.AnsiX923, PaddingMode.PKCS7, PaddingMode.ISO10126)] PaddingMode padding,
        [Values(0, 1, 15, 16, 17, 32)] int len)
    {
        byte[] plain = new byte[len];
        new Random(42).NextBytes(plain);
        byte[] copy = (byte[])plain.Clone();
        byte[] padded = BlockPadding.Apply(plain, 16, padding);
        SystemPadding platform = padding switch
        {
            PaddingMode.AnsiX923 => SystemPadding.ANSIX923,
            PaddingMode.PKCS7 => SystemPadding.PKCS7,
            _ => SystemPadding.ISO10126
        };
        using Aes aes = Aes.Create();
        byte[] encrypted = aes.EncryptEcb(padded, SystemPadding.None);
        Assert.That(aes.DecryptEcb(encrypted, platform), Is.EqualTo(plain));
        if (padding != PaddingMode.ISO10126)
            Assert.That(encrypted, Is.EqualTo(aes.EncryptEcb(plain, platform)));
        Assert.That(BlockPadding.Remove(padded, 16, padding), Is.EqualTo(plain));
        Assert.That(plain, Is.EqualTo(copy));
    }

    [TestCase(PaddingMode.PKCS7, "0102030405060700")]
    [TestCase(PaddingMode.PKCS7, "0102030405060709")]
    [TestCase(PaddingMode.PKCS7, "0102030405060102")]
    [TestCase(PaddingMode.AnsiX923, "0102030405060102")]
    [TestCase(PaddingMode.ISO10126, "0102030405060700")]
    [TestCase(PaddingMode.ISO10126, "0102030405060709")]
    public void RejectsInvalidPadding(PaddingMode padding, string hex)
    {
        Assert.Throws<CryptographicException>(() => BlockPadding.Remove(Convert.FromHexString(hex), 8, padding));
    }

    [Test]
    public void ZerosPreservesTrailingZeroBytes()
    {
        byte[] plain = new byte[33];
        plain[0] = 1;
        byte[] padded = BlockPadding.Apply(plain, 16, PaddingMode.Zeros);
        Assert.That(BlockPadding.Remove(padded, 16, PaddingMode.Zeros, plain.Length), Is.EqualTo(plain));
        Assert.Throws<ArgumentException>(() => BlockPadding.Remove(padded, 16, PaddingMode.Zeros));
        Assert.Throws<CryptographicException>(() => BlockPadding.Remove(padded, 16, PaddingMode.Zeros, 16));
        padded[^1] = 1;
        Assert.Throws<CryptographicException>(() => BlockPadding.Remove(padded, 16, PaddingMode.Zeros, plain.Length));
    }

    [TestCase(0)]
    [TestCase(-1)]
    [TestCase(256)]
    public void RejectsInvalidBlockSize(int blockSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.Apply([], blockSize, PaddingMode.PKCS7));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.Remove([], blockSize, PaddingMode.PKCS7));
    }

    [Test]
    public void RejectsInvalidArguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.Apply([], 16, (PaddingMode)99));
        Assert.Throws<ArgumentException>(() => BlockPadding.Remove(new byte[15], 16, PaddingMode.PKCS7));
        Assert.Throws<CryptographicException>(() => BlockPadding.Remove([], 16, PaddingMode.PKCS7));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.Remove(new byte[16], 16, PaddingMode.Zeros, -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.Remove(new byte[16], 16, PaddingMode.Zeros, 17));
    }
}
