using System.Numerics;
using System.Security.Cryptography;

namespace Cryptography.Core;

public class DiffieHellman
{
    public const int PublicKeySize = 384;
    private const int Generator = 2;

    private static readonly BigInteger mod = new BigInteger(Convert.FromHexString(
        "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
        "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
        "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
        "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
        "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
        "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
        "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
        "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
        "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
        "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
        "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238" +
        "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C" +
        "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3" +
        "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D" +
        "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF" +
        "3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF"), isUnsigned: true, isBigEndian: true);

    private static readonly BigInteger order = (mod - 1) / 2;

    private BigInteger privateKey;
    private byte[] publicKey;

    public DiffieHellman() : this(CreatePrivateKey()) { }

    public DiffieHellman(byte[] privateKey) : this(ReadPrivateKey(privateKey)) { }

    private DiffieHellman(BigInteger privateKey)
    {
        if (privateKey < 2 || privateKey > order - 2)
            throw new ArgumentOutOfRangeException(nameof(privateKey), "Закрытый ключ должен быть от 2 до q - 2");

        this.privateKey = privateKey;
        publicKey = ToBytes(BigInteger.ModPow(Generator, privateKey, mod));
    }

    public byte[] GetPublicKey() => (byte[])publicKey.Clone();

    public byte[] GetSharedSecret(byte[] peerPublicKey)
    {
        ArgumentNullException.ThrowIfNull(peerPublicKey);
        if (peerPublicKey.Length != PublicKeySize)
            throw new ArgumentException($"Открытый ключ должен содержать {PublicKeySize} байт", nameof(peerPublicKey));

        BigInteger peerKey = new BigInteger(peerPublicKey, isUnsigned: true, isBigEndian: true);
        if (peerKey < 2 || peerKey > mod - 2 || BigInteger.ModPow(peerKey, order, mod) != 1)
            throw new CryptographicException("Открытый ключ не принадлежит подгруппе ffdhe3072");

        return ToBytes(BigInteger.ModPow(peerKey, privateKey, mod));
    }

    public byte[] DeriveSessionKey(byte[] peerPublicKey, int keySize = 32,
        ReadOnlySpan<byte> salt = default, ReadOnlySpan<byte> info = default)
    {
        if (keySize is not (16 or 24 or 32))
            throw new ArgumentOutOfRangeException(nameof(keySize), "Сессионный ключ должен содержать 16, 24 или 32 байта");

        byte[] secret = GetSharedSecret(peerPublicKey);
        try
        {
            byte[] res = new byte[keySize];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, res, salt, info);
            return res;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static BigInteger CreatePrivateKey()
    {
        Span<byte> buf = stackalloc byte[PublicKeySize];
        BigInteger key;
        do
        {
            RandomNumberGenerator.Fill(buf);
            key = new BigInteger(buf, isUnsigned: true, isBigEndian: true);
        } while (key < 2 || key > order - 2);

        CryptographicOperations.ZeroMemory(buf);
        return key;
    }

    private static BigInteger ReadPrivateKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length < 1 || key.Length > PublicKeySize)
            throw new ArgumentException($"Закрытый ключ должен содержать от 1 до {PublicKeySize} байт", nameof(key));

        return new BigInteger(key, isUnsigned: true, isBigEndian: true);
    }

    private static byte[] ToBytes(BigInteger value)
    {
        byte[] res = new byte[PublicKeySize];
        value.TryWriteBytes(res, out _, isUnsigned: true, isBigEndian: false);
        Array.Reverse(res);
        return res;
    }
}
