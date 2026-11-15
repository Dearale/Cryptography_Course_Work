using Cryptography.Core;
using Aes = System.Security.Cryptography.Aes;
using SystemPadding = System.Security.Cryptography.PaddingMode;

namespace Cryptography.Tests;

public class AesBlockCipher : ISymmetricCipher
{
    private byte[] key = new byte[16];
    public int BlockSize => 16;

    public void SetKey(byte[] value) => key = (byte[])value.Clone();

    public byte[] Encrypt(byte[] block)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        return aes.EncryptEcb(block, SystemPadding.None);
    }

    public byte[] Decrypt(byte[] block)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        return aes.DecryptEcb(block, SystemPadding.None);
    }
}

public class TestBlockCipher : ISymmetricCipher
{
    private byte[] key;
    public int BlockSize { get; }

    public TestBlockCipher(int blockSize)
    {
        BlockSize = blockSize;
        key = new byte[blockSize];
    }

    public void SetKey(byte[] value) => key = (byte[])value.Clone();

    public byte[] Encrypt(byte[] block)
    {
        byte[] res = new byte[BlockSize];
        for (int i = 0; i < BlockSize; i++)
            res[i] = (byte)(block[(i + 1) % BlockSize] ^ key[i]);
        return res;
    }

    public byte[] Decrypt(byte[] block)
    {
        byte[] res = new byte[BlockSize];
        for (int i = 0; i < BlockSize; i++)
            res[(i + 1) % BlockSize] = (byte)(block[i] ^ key[i]);
        return res;
    }
}
