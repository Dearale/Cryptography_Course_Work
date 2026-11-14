using Cryptography.Core;

namespace Cryptography.Tests;

public class Rc6ComponentsTests
{
    [TestCase("0123456789ABCDEF0112233445566778", "524E192F4715C6231F51F6367EA43F18")]
    [TestCase("0123456789ABCDEF0112233445566778899AABBCCDDEEFF0", "688329D019E505041E52E92AF95291D4")]
    [TestCase("0123456789ABCDEF0112233445566778899AABBCCDDEEFF01032547698BADCFE", "C8241816F0D7E48920AD16A1674E5D48")]
    public void NonZeroVectorMatchesSpecification(string keyHex, string expectedHex)
    {
        Rc6 cipher = new Rc6();
        byte[] data = Convert.FromHexString("02132435465768798A9BACBDCEDFE0F1");
        byte[] expected = Convert.FromHexString(expectedHex);
        cipher.SetKey(Convert.FromHexString(keyHex));

        Assert.That(cipher.Encrypt(data), Is.EqualTo(expected));
        Assert.That(cipher.Decrypt(expected), Is.EqualTo(data));
    }

    [Test]
    public void CipherPreservesCallerBuffersAndDoesNotKeepCallerKey()
    {
        Rc6 cipher = new Rc6();
        byte[] key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        byte[] data = (byte[])key.Clone();
        byte[] copy = (byte[])key.Clone();
        byte[] expected = Convert.FromHexString("3A96F9C7F6755CFE46F00E3DCD5D2A3C");
        cipher.SetKey(key);

        Assert.That(key, Is.EqualTo(copy));
        Array.Fill(key, (byte)0);
        Assert.That(cipher.Encrypt(data), Is.EqualTo(expected));
        Assert.That(data, Is.EqualTo(copy));
        Assert.That(cipher.Decrypt(expected), Is.EqualTo(copy));
        Assert.That(Convert.ToHexString(expected), Is.EqualTo("3A96F9C7F6755CFE46F00E3DCD5D2A3C"));
    }

    [Test]
    public void RoundDecryptRestoresStateAndPreservesRoundKey()
    {
        IRoundEncryptor<uint> round = new Rc6RoundEncryptor();
        uint[] words = { 0xFFFFFFFF, 0x80000003, 0, 0x12345678 };
        uint[] copy = (uint[])words.Clone();
        uint[] roundKey = { 0xFFFFFFFF, 0xABCDEF01 };
        uint[] keyCopy = (uint[])roundKey.Clone();

        round.Encrypt(words, roundKey);
        round.Decrypt(words, roundKey);

        Assert.That(words, Is.EqualTo(copy));
        Assert.That(roundKey, Is.EqualTo(keyCopy));
    }

    [TestCase(3, 2)]
    [TestCase(5, 2)]
    [TestCase(4, 1)]
    [TestCase(4, 3)]
    public void RoundRejectsInvalidSizes(int blockLen, int keyLen)
    {
        IRoundEncryptor<uint> round = new Rc6RoundEncryptor();
        uint[] words = new uint[blockLen];
        uint[] roundKey = new uint[keyLen];

        Assert.Throws<ArgumentException>(() => round.Encrypt(words, roundKey));
        Assert.Throws<ArgumentException>(() => round.Decrypt(words, roundKey));
    }

    [Test]
    public void ConcurrentCallsWithOneKeyMatchSequentialCalls()
    {
        Rc6 cipher = new Rc6();
        Random random = new Random(42);
        byte[] key = new byte[32];
        random.NextBytes(key);
        cipher.SetKey(key);

        byte[][] data = new byte[256][];
        byte[][] expected = new byte[data.Length][];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = new byte[cipher.BlockSize];
            random.NextBytes(data[i]);
            expected[i] = cipher.Encrypt(data[i]);
        }

        Parallel.For(0, data.Length, i =>
        {
            byte[] encrypted = cipher.Encrypt(data[i]);
            Assert.That(encrypted, Is.EqualTo(expected[i]));
            Assert.That(cipher.Decrypt(encrypted), Is.EqualTo(data[i]));
        });
    }
}
