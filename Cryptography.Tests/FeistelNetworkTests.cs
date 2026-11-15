using Cryptography.Core;

namespace Cryptography.Tests;

public class FeistelNetworkTests
{
    // F(x, k) = (x + k) mod 256; ключи различаются, чтобы проверить их порядок.
    [TestCase("0123", "216174C4")]
    [TestCase("012345", "74C49868")]
    public void MatchesManualTransform(string keyHex, string cipherHex)
    {
        FeistelNetwork cipher = new FeistelNetwork(new TestKeyExpansion(), new TestRoundFunction(), 4);
        byte[] plain = Convert.FromHexString("10203040");
        byte[] expected = Convert.FromHexString(cipherHex);
        cipher.SetKey(Convert.FromHexString(keyHex));

        Assert.That(cipher.Encrypt(plain), Is.EqualTo(expected));
        Assert.That(cipher.Decrypt(expected), Is.EqualTo(plain));
        Assert.That(Convert.ToHexString(plain), Is.EqualTo("10203040"));
        Assert.That(Convert.ToHexString(expected), Is.EqualTo(cipherHex));
    }

    [TestCase(-2)]
    [TestCase(0)]
    [TestCase(1)]
    [TestCase(3)]
    public void ConstructorRejectsInvalidBlockSize(int blockSize)
    {
        Assert.Throws<ArgumentException>(() =>
            new FeistelNetwork(new TestKeyExpansion(), new TestRoundFunction(), blockSize));
    }

    [Test]
    public void ConstructorRejectsNullDependencies()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new FeistelNetwork(null!, new TestRoundFunction(), 4));
        Assert.Throws<ArgumentNullException>(() =>
            new FeistelNetwork(new TestKeyExpansion(), null!, 4));
    }

    [Test]
    public void MissingKeyIsRejected()
    {
        FeistelNetwork cipher = new FeistelNetwork(new TestKeyExpansion(), new TestRoundFunction(), 4);
        Assert.Throws<InvalidOperationException>(() => cipher.Encrypt(new byte[4]));
        Assert.Throws<InvalidOperationException>(() => cipher.Decrypt(new byte[4]));
    }

    [Test]
    public void NullArgumentsAreRejected()
    {
        FeistelNetwork cipher = new FeistelNetwork(new TestKeyExpansion(), new TestRoundFunction(), 4);
        Assert.Throws<ArgumentNullException>(() => cipher.SetKey(null!));
        cipher.SetKey([1]);
        Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(null!));
        Assert.Throws<ArgumentNullException>(() => cipher.Decrypt(null!));
    }

    [TestCase(0)]
    [TestCase(3)]
    [TestCase(5)]
    public void InvalidBlockSizeIsRejected(int len)
    {
        FeistelNetwork cipher = new FeistelNetwork(new TestKeyExpansion(), new TestRoundFunction(), 4);
        cipher.SetKey([1]);
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[len]));
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(new byte[len]));
    }

    [Test]
    public void EmptySchedulePreservesCurrentKey()
    {
        FeistelNetwork cipher = new FeistelNetwork(new TestKeyExpansion(), new TestRoundFunction(), 4);
        cipher.SetKey([1, 2]);
        byte[] plain = Convert.FromHexString("10203040");
        byte[] expected = cipher.Encrypt(plain);

        Assert.Throws<InvalidOperationException>(() => cipher.SetKey([]));
        Assert.That(cipher.Encrypt(plain), Is.EqualTo(expected));
    }

    [TestCase(4)]
    [TestCase(1024)]
    public void HandlesSmallAndLargeBlocks(int blockSize)
    {
        FeistelNetwork cipher = new FeistelNetwork(new TestKeyExpansion(), new TestRoundFunction(), blockSize);
        cipher.SetKey([1]);
        byte[] plain = new byte[blockSize];
        byte[] expected = new byte[blockSize];
        Array.Fill(plain, (byte)0x10, 0, blockSize / 2);
        Array.Fill(plain, (byte)0x20, blockSize / 2, blockSize / 2);
        Array.Fill(expected, (byte)0x20, 0, blockSize / 2);
        Array.Fill(expected, (byte)0x31, blockSize / 2, blockSize / 2);

        Assert.That(cipher.Encrypt(plain), Is.EqualTo(expected));
        Assert.That(cipher.Decrypt(expected), Is.EqualTo(plain));
    }

    [Test]
    public void AllocationsDoNotGrowWithRoundCount()
    {
        FeistelNetwork shortCipher = new FeistelNetwork(new TestKeyExpansion(), new TestRoundFunction(), 16);
        FeistelNetwork longCipher = new FeistelNetwork(new TestKeyExpansion(), new TestRoundFunction(), 16);
        shortCipher.SetKey([1]);
        longCipher.SetKey(new byte[32]);
        byte[] block = new byte[16];

        long shortAlloc = MeasureAllocations(shortCipher, block);
        long longAlloc = MeasureAllocations(longCipher, block);
        Assert.That(longAlloc, Is.EqualTo(shortAlloc));
    }

    private static long MeasureAllocations(FeistelNetwork cipher, byte[] block)
    {
        for (int i = 0; i < 100; i++)
            GC.KeepAlive(cipher.Encrypt(block));
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 200; i++)
            GC.KeepAlive(cipher.Encrypt(block));
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    private class TestKeyExpansion : IKeyExpansion<byte[]>
    {
        public byte[][] ExpandKey(byte[] key)
        {
            byte[][] res = new byte[key.Length][];
            for (int i = 0; i < key.Length; i++)
                res[i] = [key[i]];
            return res;
        }
    }

    private class TestRoundFunction : IFeistelRoundFunction
    {
        public void Encrypt(ReadOnlySpan<byte> half, ReadOnlySpan<byte> roundKey, Span<byte> res)
        {
            for (int i = 0; i < half.Length; i++)
                res[i] = unchecked((byte)(half[i] + roundKey[0]));
        }
    }
}
