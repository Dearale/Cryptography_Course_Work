namespace Cryptography.Core;

public class FeistelNetwork : ISymmetricCipher
{
    private IKeyExpansion<byte[]> keyExpansion;
    private IFeistelRoundFunction roundFunction;
    private byte[][]? roundKeys;

    public int BlockSize { get; }

    public FeistelNetwork(IKeyExpansion<byte[]> keyExpansion, IFeistelRoundFunction roundFunction, int blockSize)
    {
        ArgumentNullException.ThrowIfNull(keyExpansion);
        ArgumentNullException.ThrowIfNull(roundFunction);
        if (blockSize <= 0 || blockSize % 2 != 0)
            throw new ArgumentException("Размер блока должен быть положительным и четным", nameof(blockSize));

        this.keyExpansion = keyExpansion;
        this.roundFunction = roundFunction;
        BlockSize = blockSize;
    }

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        byte[][] expanded = keyExpansion.ExpandKey(key);
        if (expanded == null || expanded.Length == 0)
            throw new InvalidOperationException("Генератор ключей не создал ни одного раундового ключа");
        roundKeys = expanded;
    }

    public byte[] Encrypt(byte[] block) => ProcessBlock(block, false);

    public byte[] Decrypt(byte[] block) => ProcessBlock(block, true);

    private byte[] ProcessBlock(byte[] block, bool decrypt)
    {
        ValidateBlock(block);
        if (roundKeys == null)
            throw new InvalidOperationException("Ключ не установлен");

        byte[] res = (byte[])block.Clone();

        int halfSize = BlockSize / 2;

        Span<byte> left = res.AsSpan(0, halfSize);
        Span<byte> right = res.AsSpan(halfSize);
        Span<byte> mask = stackalloc byte[halfSize];

        if (decrypt)
        {
            Span<byte> temp = left;
            left = right;
            right = temp;
        }

        for (int i = 0; i < roundKeys.Length; i++)
        {
            int keyIdx = decrypt ? roundKeys.Length - 1 - i : i;
            roundFunction.Encrypt(right, roundKeys[keyIdx], mask);
            for (int j = 0; j < halfSize; j++)
            {
                byte prev = left[j];
                left[j] = right[j];
                right[j] = (byte)(prev ^ mask[j]);
            }
        }

        return res;
    }

    private void ValidateBlock(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSize)
            throw new ArgumentException($"Размер блока должен быть равен {BlockSize} байт", nameof(block));
    }
}
