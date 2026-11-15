using System.Numerics;
using Cryptography.Core;
using CryptographicException = System.Security.Cryptography.CryptographicException;

namespace Cryptography.Tests;

public class SymmetricCipherContextTests
{
    [TestCase(CipherMode.ECB, "000102030405060708090A0B0C0D0E0F",
        "3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4")]
    [TestCase(CipherMode.CBC, "000102030405060708090A0B0C0D0E0F",
        "7649ABAC8119B246CEE98E9B12E9197D" +
        "5086CB9B507219EE95DB113A917678B2" +
        "73BED6B8E3C1743B7116E69E22229516" +
        "3FF1CAA1681FAC09120ECA307586E1A7")]
    [TestCase(CipherMode.CFB, "000102030405060708090A0B0C0D0E0F",
        "3B3FD92EB72DAD20333449F8E83CFB4AC8A64537A0B3A93FCDE3CDAD9F1CE58B26751F67A3CBB140B1808CF187A4F4DFC04B05357C5D1C0EEAC4C66F9FF7F2E6")]
    [TestCase(CipherMode.OFB, "000102030405060708090A0B0C0D0E0F",
        "3B3FD92EB72DAD20333449F8E83CFB4A" +
        "7789508D16918F03F53C52DAC54ED825" +
        "9740051E9C5FECF64344F7A82260EDCC" +
        "304C6528F659C77866A510D9C1D6AE5E")]
    [TestCase(CipherMode.CTR, "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
        "874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE")]
    [Description("NIST SP 800-38A, Appendix F: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf")]
    public async Task MatchesNistVectors(CipherMode mode, string ivHex, string cipherHex)
    {
        byte[] key = Convert.FromHexString("2B7E151628AED2A6ABF7158809CF4F3C");
        byte[] plain = Convert.FromHexString(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
        SymmetricCipherContext context = new SymmetricCipherContext(new AesBlockCipher(), key,
            mode, PaddingMode.Zeros, Convert.FromHexString(ivHex));
        byte[] expected = Convert.FromHexString(cipherHex);

        Assert.That(await context.EncryptAsync(plain), Is.EqualTo(expected));
        Assert.That(await context.DecryptAsync(expected, plain.Length), Is.EqualTo(plain));
    }

    [TestCase(CipherMode.PCBC, "AABB", "000102030405", "BBA8ABBBBCAF", 1)]
    [TestCase(CipherMode.CTR, "FFFE", "000000000000", "FFFDFEFD0102", 1)]
    [TestCase(CipherMode.RandomDelta, "FFFE", "000000000000", "FFFD00020502", 3)]
    public async Task MatchesManualTransform(CipherMode mode, string ivHex, string plainHex,
        string cipherHex, int delta)
    {
        SymmetricCipherContext context = new SymmetricCipherContext(new TestBlockCipher(2), [1, 2],
            mode, PaddingMode.Zeros, Convert.FromHexString(ivHex), new BigInteger(delta));
        byte[] plain = Convert.FromHexString(plainHex);
        byte[] expected = Convert.FromHexString(cipherHex);
        Assert.That(await context.EncryptAsync(plain), Is.EqualTo(expected));
        Assert.That(await context.DecryptAsync(expected, plain.Length), Is.EqualTo(plain));
    }

    [Test]
    public async Task HandlesAllCipherModeAndPaddingCombinations(
        [Values(false, true)] bool useMagenta, [Values] CipherMode mode, [Values] PaddingMode padding,
        [Values(0, 1, 15, 16, 17, 255)] int len)
    {
        ISymmetricCipher cipher = useMagenta ? new Magenta() : new Rc6();
        SymmetricCipherContext context = CreateContext(cipher, mode, padding);
        byte[] plain = CreateData(len);
        byte[] plainCopy = (byte[])plain.Clone();
        byte[] encrypted = await context.EncryptAsync(plain);
        byte[] encryptedCopy = (byte[])encrypted.Clone();

        Assert.That(await context.DecryptAsync(encrypted, len), Is.EqualTo(plain));
        Assert.That(plain, Is.EqualTo(plainCopy));
        Assert.That(encrypted, Is.EqualTo(encryptedCopy));
    }

    [Test]
    public async Task ConcurrentOperationsHaveIndependentState([Values] CipherMode mode)
    {
        SymmetricCipherContext context = CreateContext(new Rc6(), mode, PaddingMode.PKCS7);
        byte[] first = CreateData(47);
        byte[] second = CreateData(113);
        byte[] expectedFirst = await context.EncryptAsync(first);
        byte[] expectedSecond = await context.EncryptAsync(second);
        byte[][] encrypted = await Task.WhenAll(context.EncryptAsync(first), context.EncryptAsync(second));
        Assert.That(encrypted[0], Is.EqualTo(expectedFirst));
        Assert.That(encrypted[1], Is.EqualTo(expectedSecond));
        byte[][] decrypted = await Task.WhenAll(context.DecryptAsync(encrypted[0]), context.DecryptAsync(encrypted[1]));
        Assert.That(decrypted[0], Is.EqualTo(first));
        Assert.That(decrypted[1], Is.EqualTo(second));
    }

    [Test]
    public async Task CallerIvAndKeyAreNotRetained()
    {
        byte[] key = CreateData(16);
        byte[] iv = CreateData(16);
        SymmetricCipherContext context = new SymmetricCipherContext(new Rc6(), key,
            CipherMode.CTR, PaddingMode.PKCS7, iv);
        byte[] plain = CreateData(47);
        byte[] expected = await context.EncryptAsync(plain);
        Array.Fill(key, (byte)0xFF);
        Array.Fill(iv, (byte)0xFF);
        Assert.That(await context.EncryptAsync(plain), Is.EqualTo(expected));
    }

    [Test]
    public void RejectsInvalidConfiguration()
    {
        Assert.Throws<ArgumentNullException>(() => new SymmetricCipherContext(null!, new byte[16], CipherMode.ECB, PaddingMode.PKCS7));
        Assert.Throws<ArgumentNullException>(() => new SymmetricCipherContext(new Rc6(), null!, CipherMode.ECB, PaddingMode.PKCS7));
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            new SymmetricCipherContext(new Rc6(), new byte[16], (CipherMode)99, PaddingMode.PKCS7, new byte[16]).EncryptAsync([]));
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            new SymmetricCipherContext(new Rc6(), new byte[16], CipherMode.ECB, (PaddingMode)99).EncryptAsync([]));
        Assert.Throws<ArgumentException>(() => new SymmetricCipherContext(new Rc6(), new byte[16], CipherMode.CBC, PaddingMode.PKCS7));
        Assert.Throws<ArgumentException>(() => new SymmetricCipherContext(new Rc6(), new byte[16], CipherMode.CBC, PaddingMode.PKCS7, new byte[15]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SymmetricCipherContext(new Rc6(), new byte[16], CipherMode.RandomDelta, PaddingMode.PKCS7, new byte[16]));
        foreach (BigInteger delta in new BigInteger[] { -1, 0, BigInteger.One << 128 })
            Assert.Throws<ArgumentOutOfRangeException>(() => new SymmetricCipherContext(new Rc6(), new byte[16], CipherMode.RandomDelta, PaddingMode.PKCS7, new byte[16], delta));
    }

    [Test]
    public void RejectsInvalidCiphertext()
    {
        SymmetricCipherContext context = CreateContext(new Rc6(), CipherMode.CBC, PaddingMode.PKCS7);
        Assert.Throws<ArgumentException>(() => context.DecryptAsync(new byte[15]));
        Assert.Throws<CryptographicException>(() => context.DecryptAsync([]));
        SymmetricCipherContext zeros = CreateContext(new Rc6(), CipherMode.CBC, PaddingMode.Zeros);
        Assert.Throws<ArgumentException>(() => zeros.DecryptAsync(new byte[16]));
        Assert.Throws<CryptographicException>(() => zeros.DecryptAsync(new byte[32], 16));
        Assert.Throws<ArgumentOutOfRangeException>(() => zeros.DecryptAsync(new byte[16], 17));
    }

    [Test]
    public void SupportsCancellation()
    {
        SymmetricCipherContext context = CreateContext(new Rc6(), CipherMode.ECB, PaddingMode.PKCS7);
        CancellationToken token = new CancellationToken(true);
        Assert.That(async () => await context.EncryptAsync([], token), Throws.InstanceOf<OperationCanceledException>());
        Assert.That(async () => await context.DecryptAsync(new byte[16], cancellationToken: token), Throws.InstanceOf<OperationCanceledException>());
    }

    public static SymmetricCipherContext CreateContext(ISymmetricCipher cipher, CipherMode mode, PaddingMode padding)
    {
        byte[] key = CreateData(cipher.BlockSize);
        byte[] iv = Enumerable.Repeat((byte)0xFF, cipher.BlockSize).ToArray();
        return new SymmetricCipherContext(cipher, key, mode, padding, mode == CipherMode.ECB ? null : iv, new BigInteger(257));
    }

    public static byte[] CreateData(int len)
    {
        byte[] data = new byte[len];
        new Random(42).NextBytes(data);
        data.AsSpan(Math.Max(0, len - 32)).Clear();
        return data;
    }
}
