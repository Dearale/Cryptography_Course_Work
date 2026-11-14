using System.Buffers.Binary;

namespace Cryptography.Core;

public class Rc6 : ISymmetricCipher
{
    private IKeyExpansion<uint> keyExpansion = new Rc6KeyExpansion();
    private IRoundEncryptor<uint> roundEncryptor = new Rc6RoundEncryptor();
    private uint[]? keys;

    public int BlockSize => 16;

    public void SetKey(byte[] key)
    {
        keys = keyExpansion.ExpandKey(key);
    }

    public byte[] Encrypt(byte[] block)
    {
        if (keys == null)
            throw new InvalidOperationException("Ключ не установлен");

        Span<uint> words = stackalloc uint[4];
        ReadBlock(block, words);

        unchecked
        {
            words[1] += keys[0];
            words[3] += keys[1];

            for (int i = 2; i < keys.Length - 2; i += 2)
                roundEncryptor.Encrypt(words, keys.AsSpan(i, 2));

            words[0] += keys[^2];
            words[2] += keys[^1];
        }

        return WriteBlock(words);
    }

    public byte[] Decrypt(byte[] block)
    {
        if (keys == null)
            throw new InvalidOperationException("Ключ не установлен");

        Span<uint> words = stackalloc uint[4];
        ReadBlock(block, words);

        unchecked
        {
            words[2] -= keys[^1];
            words[0] -= keys[^2];

            for (int i = keys.Length - 4; i >= 2; i -= 2)
                roundEncryptor.Decrypt(words, keys.AsSpan(i, 2));

            words[3] -= keys[1];
            words[1] -= keys[0];
        }

        return WriteBlock(words);
    }

    private void ReadBlock(byte[] block, Span<uint> words)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSize)
            throw new ArgumentException("Блок RC6 должен иметь 16 байт", nameof(block));

        for (int i = 0; i < words.Length; i++)
            words[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(i * 4));
    }

    private byte[] WriteBlock(Span<uint> words)
    {
        byte[] res = new byte[BlockSize];
        for (int i = 0; i < words.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(res.AsSpan(i * 4), words[i]);
        return res;
    }
}
