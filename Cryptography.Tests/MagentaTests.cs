using Cryptography.Core;

namespace Cryptography.Tests;

public class MagentaTests
{
    public static IEnumerable<TestCaseData> KnownVectors()
    {
        string path = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestData", "MagentaKat.txt");
        foreach (string line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                continue;
            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            yield return new TestCaseData(parts[0], parts[1], parts[2]);
        }
    }

    [TestCaseSource(nameof(KnownVectors))]
    public void MatchesKnownVector(string keyHex, string plainHex, string cipherHex)
    {
        ISymmetricCipher cipher = new Magenta();
        byte[] data = Convert.FromHexString(plainHex);
        byte[] expected = Convert.FromHexString(cipherHex);
        cipher.SetKey(Convert.FromHexString(keyHex));

        Assert.That(cipher.Encrypt(data), Is.EqualTo(expected));
        Assert.That(cipher.Decrypt(expected), Is.EqualTo(data));
    }

    [Test]
    public void MissingKeyIsRejected()
    {
        Magenta cipher = new Magenta();
        Assert.Throws<InvalidOperationException>(() => cipher.Encrypt(new byte[16]));
        Assert.Throws<InvalidOperationException>(() => cipher.Decrypt(new byte[16]));
    }

    [Test]
    public void NullArgumentsAreRejected()
    {
        Magenta cipher = new Magenta();
        Assert.Throws<ArgumentNullException>(() => cipher.SetKey(null!));
        cipher.SetKey(new byte[16]);
        Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(null!));
        Assert.Throws<ArgumentNullException>(() => cipher.Decrypt(null!));
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(8)]
    [TestCase(15)]
    [TestCase(17)]
    [TestCase(23)]
    [TestCase(25)]
    [TestCase(31)]
    [TestCase(33)]
    public void InvalidKeySizeIsRejected(int len)
    {
        Magenta cipher = new Magenta();
        Assert.Throws<ArgumentException>(() => cipher.SetKey(new byte[len]));
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(8)]
    [TestCase(15)]
    [TestCase(17)]
    [TestCase(32)]
    public void InvalidBlockSizeIsRejected(int len)
    {
        Magenta cipher = new Magenta();
        cipher.SetKey(new byte[16]);
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[len]));
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(new byte[len]));
    }

    [TestCase(16)]
    [TestCase(24)]
    [TestCase(32)]
    public void CallerBuffersArePreservedAndCallerKeyIsNotRetained(int keyLen)
    {
        Magenta cipher = new Magenta();
        Random random = new Random(42);
        byte[] key = new byte[keyLen];
        byte[] data = new byte[16];
        random.NextBytes(key);
        random.NextBytes(data);
        byte[] keyCopy = (byte[])key.Clone();
        byte[] dataCopy = (byte[])data.Clone();
        cipher.SetKey(key);

        Assert.That(key, Is.EqualTo(keyCopy));
        byte[] encrypted = cipher.Encrypt(data);
        byte[] encryptedCopy = (byte[])encrypted.Clone();
        Assert.That(data, Is.EqualTo(dataCopy));
        Assert.That(cipher.Decrypt(encrypted), Is.EqualTo(dataCopy));
        Assert.That(encrypted, Is.EqualTo(encryptedCopy));

        Array.Fill(key, (byte)0);
        Assert.That(cipher.Encrypt(data), Is.EqualTo(encryptedCopy));
    }

    [Test]
    public void InvalidKeyDoesNotReplaceCurrentKey()
    {
        Magenta cipher = new Magenta();
        cipher.SetKey(Convert.FromHexString("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0"));
        byte[] data = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        byte[] expected = Convert.FromHexString("0909105491F0EF3D363EAE828A504E2B");

        Assert.Throws<ArgumentException>(() => cipher.SetKey(new byte[17]));
        Assert.That(cipher.Encrypt(data), Is.EqualTo(expected));
    }

    [Test]
    public void RoundFunctionPreservesInputsAndOverwritesResult()
    {
        IFeistelRoundFunction round = new MagentaRoundEncryptor();
        byte[] half = Convert.FromHexString("0001020304050607");
        byte[] copy = (byte[])half.Clone();
        byte[] key = Convert.FromHexString("FFEEDDCCBBAA9988");
        byte[] keyCopy = (byte[])key.Clone();
        byte[] res = new byte[8];
        byte[] other = new byte[8];
        Array.Fill(other, (byte)0xFF);

        round.Encrypt(half, key, res);
        round.Encrypt(half, key, other);

        Assert.That(half, Is.EqualTo(copy));
        Assert.That(key, Is.EqualTo(keyCopy));
        Assert.That(other, Is.EqualTo(res));
    }

    [TestCase(0, 8, 8)]
    [TestCase(7, 8, 8)]
    [TestCase(9, 8, 8)]
    [TestCase(8, 0, 8)]
    [TestCase(8, 7, 8)]
    [TestCase(8, 9, 8)]
    [TestCase(8, 8, 0)]
    [TestCase(8, 8, 7)]
    [TestCase(8, 8, 9)]
    public void RoundRejectsInvalidSizes(int halfLen, int keyLen, int resLen)
    {
        IFeistelRoundFunction round = new MagentaRoundEncryptor();
        byte[] half = new byte[halfLen];
        byte[] key = new byte[keyLen];
        byte[] res = new byte[resLen];
        Assert.Throws<ArgumentException>(() => round.Encrypt(half, key, res));
    }

    [TestCase(16)]
    [TestCase(24)]
    [TestCase(32)]
    public void ConcurrentCallsWithOneKeyMatchSequentialCalls(int keyLen)
    {
        Magenta cipher = new Magenta();
        Random random = new Random(42);
        byte[] key = new byte[keyLen];
        random.NextBytes(key);
        cipher.SetKey(key);

        byte[][] data = new byte[128][];
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
