using System.Numerics;
using System.Text;
using System.Text.Json;
using Cryptography.Core;
using CryptographicException = System.Security.Cryptography.CryptographicException;

namespace Cryptography.Tests;

public class DiffieHellmanTests
{
    private static readonly JsonElement vector = LoadVector();

    [Test]
    [Description("Published ffdhe3072 vector: https://lkml.iu.edu/2112.1/01503.html")]
    public void MatchesPublishedPublicKeyAndSharedSecret()
    {
        DiffieHellman exchange = new DiffieHellman(ReadBytes("privateKey"));
        byte[] peerKey = ReadBytes("peerPublicKey");
        byte[] copy = (byte[])peerKey.Clone();

        Assert.That(exchange.GetPublicKey(), Is.EqualTo(ReadBytes("publicKey")));
        Assert.That(exchange.GetSharedSecret(peerKey), Is.EqualTo(ReadBytes("sharedSecret")));
        Assert.That(peerKey, Is.EqualTo(copy));
    }

    [TestCase(16)]
    [TestCase(24)]
    [TestCase(32)]
    [Description("HKDF-SHA256 reference independently computed with Node.js crypto.hkdfSync")]
    public void SessionKeyMatchesIndependentReference(int keySize)
    {
        DiffieHellman exchange = new DiffieHellman(ReadBytes("privateKey"));
        byte[] salt = ReadBytes("salt");
        byte[] info = ReadBytes("info");
        byte[] saltCopy = (byte[])salt.Clone();
        byte[] infoCopy = (byte[])info.Clone();
        byte[] expected = Convert.FromHexString(vector.GetProperty("sessionKeys")
            .GetProperty(keySize.ToString()).GetString()!);

        Assert.That(exchange.DeriveSessionKey(ReadBytes("peerPublicKey"), keySize, salt, info), Is.EqualTo(expected));
        Assert.That(salt, Is.EqualTo(saltCopy));
        Assert.That(info, Is.EqualTo(infoCopy));
    }

    [Test]
    public void GeneratedPeersAgree()
    {
        DiffieHellman alice = new DiffieHellman();
        DiffieHellman bob = new DiffieHellman();
        byte[] aliceKey = alice.GetPublicKey();
        byte[] bobKey = bob.GetPublicKey();

        Assert.That(aliceKey, Has.Length.EqualTo(DiffieHellman.PublicKeySize));
        Assert.That(bobKey, Is.Not.EqualTo(aliceKey));
        Assert.That(alice.GetSharedSecret(bobKey), Is.EqualTo(bob.GetSharedSecret(aliceKey)));
    }

    [TestCase(2, 4)]
    [TestCase(4, 16)]
    [TestCase(16, 256)]
    public void PreservesLeadingZeros(int peerValue, int secretValue)
    {
        DiffieHellman exchange = new DiffieHellman([2]);
        Assert.That(exchange.GetPublicKey(), Is.EqualTo(ToBytes(4)));
        Assert.That(exchange.GetSharedSecret(ToBytes(peerValue)), Is.EqualTo(ToBytes(secretValue)));
    }

    [Test]
    public void RejectsInvalidPrivateKeyArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new DiffieHellman(null!));
        Assert.Throws<ArgumentException>(() => new DiffieHellman([]));
        Assert.Throws<ArgumentException>(() => new DiffieHellman(new byte[DiffieHellman.PublicKeySize + 1]));
    }

    [Test]
    public void RejectsPrivateKeyOutsideRange()
    {
        BigInteger mod = new BigInteger(ReadBytes("mod"), isUnsigned: true, isBigEndian: true);
        BigInteger order = (mod - 1) / 2;
        foreach (BigInteger key in new BigInteger[] { 0, 1, order - 1, order, mod - 1 })
            Assert.Throws<ArgumentOutOfRangeException>(() => new DiffieHellman(key.ToByteArray(isUnsigned: true, isBigEndian: true)));
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(383)]
    [TestCase(385)]
    public void RejectsInvalidPublicKeySize(int len)
    {
        DiffieHellman exchange = new DiffieHellman([2]);
        Assert.Throws<ArgumentException>(() => exchange.GetSharedSecret(new byte[len]));
    }

    [Test]
    public void RejectsNullPublicKey()
    {
        DiffieHellman exchange = new DiffieHellman([2]);
        Assert.Throws<ArgumentNullException>(() => exchange.GetSharedSecret(null!));
        Assert.Throws<ArgumentNullException>(() => exchange.DeriveSessionKey(null!));
    }

    [Test]
    public void RejectsPublicKeyOutsideRange()
    {
        DiffieHellman exchange = new DiffieHellman([2]);
        BigInteger mod = new BigInteger(ReadBytes("mod"), isUnsigned: true, isBigEndian: true);
        foreach (BigInteger key in new BigInteger[] { 0, 1, mod - 1, mod, mod + 1 })
            Assert.Throws<CryptographicException>(() => exchange.GetSharedSecret(ToBytes(key)));
    }

    [Test]
    public void RejectsPublicKeyOutsideSubgroup()
    {
        DiffieHellman exchange = new DiffieHellman([2]);
        BigInteger mod = new BigInteger(ReadBytes("mod"), isUnsigned: true, isBigEndian: true);
        Assert.Throws<CryptographicException>(() => exchange.GetSharedSecret(ToBytes(mod - 2)));
    }

    [Test]
    public void CallerCannotChangeStoredKeys()
    {
        byte[] key = ReadBytes("privateKey");
        DiffieHellman exchange = new DiffieHellman(key);
        Array.Clear(key);
        byte[] publicKey = exchange.GetPublicKey();
        Array.Clear(publicKey);

        Assert.That(exchange.GetPublicKey(), Is.EqualTo(ReadBytes("publicKey")));
        Assert.That(exchange.GetSharedSecret(ReadBytes("peerPublicKey")), Is.EqualTo(ReadBytes("sharedSecret")));
    }

    [TestCase(0)]
    [TestCase(15)]
    [TestCase(17)]
    [TestCase(23)]
    [TestCase(25)]
    [TestCase(31)]
    [TestCase(33)]
    public void RejectsInvalidSessionKeySize(int keySize)
    {
        DiffieHellman exchange = new DiffieHellman([2]);
        Assert.Throws<ArgumentOutOfRangeException>(() => exchange.DeriveSessionKey(ReadBytes("peerPublicKey"), keySize));
    }

    [Test]
    public void SaltAndInfoAffectSessionKey()
    {
        DiffieHellman exchange = new DiffieHellman([2]);
        byte[] peer = ToBytes(4);
        byte[] key = exchange.DeriveSessionKey(peer, salt: [1], info: [3]);
        Assert.That(exchange.DeriveSessionKey(peer, salt: [2], info: [3]), Is.Not.EqualTo(key));
        Assert.That(exchange.DeriveSessionKey(peer, salt: [1], info: [4]), Is.Not.EqualTo(key));
    }

    [TestCase(false)]
    [TestCase(true)]
    public async Task SessionKeysWorkWithCourseCiphers(bool useMagenta)
    {
        DiffieHellman alice = new DiffieHellman();
        DiffieHellman bob = new DiffieHellman();
        byte[] salt = ReadBytes("salt");
        byte[] info = Encoding.UTF8.GetBytes(useMagenta ? "chat:MAGENTA" : "chat:RC6");
        byte[] aliceKey = alice.DeriveSessionKey(bob.GetPublicKey(), salt: salt, info: info);
        byte[] bobKey = bob.DeriveSessionKey(alice.GetPublicKey(), salt: salt, info: info);
        Assert.That(aliceKey, Is.EqualTo(bobKey));

        ISymmetricCipher senderCipher = useMagenta ? new Magenta() : new Rc6();
        ISymmetricCipher receiverCipher = useMagenta ? new Magenta() : new Rc6();
        byte[] iv = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        SymmetricCipherContext sender = new SymmetricCipherContext(senderCipher, aliceKey, CipherMode.CBC, PaddingMode.PKCS7, iv);
        SymmetricCipherContext receiver = new SymmetricCipherContext(receiverCipher, bobKey, CipherMode.CBC, PaddingMode.PKCS7, iv);
        byte[] plain = Convert.FromHexString("0001020304FFFE000011223344556677889900");
        Assert.That(await receiver.DecryptAsync(await sender.EncryptAsync(plain)), Is.EqualTo(plain));
    }

    private static JsonElement LoadVector()
    {
        string path = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestData", "DiffieHellmanKat.json");
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));
        return document.RootElement.Clone();
    }

    private static byte[] ReadBytes(string name) => Convert.FromHexString(vector.GetProperty(name).GetString()!);

    private static byte[] ToBytes(BigInteger value)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] res = new byte[DiffieHellman.PublicKeySize];
        bytes.CopyTo(res, res.Length - bytes.Length);
        return res;
    }
}
