using System.Numerics;

namespace Cryptography.Core;

public class Rc6RoundEncryptor : IRoundEncryptor<uint>
{
    public void Encrypt(Span<uint> block, ReadOnlySpan<uint> roundKey)
    {
        ValidateArgs(block, roundKey);
        (uint a, uint b, uint c, uint d) = (block[0], block[1], block[2], block[3]);

        unchecked
        {
            uint t = BitOperations.RotateLeft(b * (2 * b + 1), 5);
            uint u = BitOperations.RotateLeft(d * (2 * d + 1), 5);
            a = BitOperations.RotateLeft(a ^ t, (int)u) + roundKey[0];
            c = BitOperations.RotateLeft(c ^ u, (int)t) + roundKey[1];
        }

        block[0] = b;
        block[1] = c;
        block[2] = d;
        block[3] = a;
    }

    public void Decrypt(Span<uint> block, ReadOnlySpan<uint> roundKey)
    {
        ValidateArgs(block, roundKey);
        (uint a, uint b, uint c, uint d) = (block[3], block[0], block[1], block[2]);

        unchecked
        {
            uint t = BitOperations.RotateLeft(b * (2 * b + 1), 5);
            uint u = BitOperations.RotateLeft(d * (2 * d + 1), 5);
            c = BitOperations.RotateRight(c - roundKey[1], (int)t) ^ u;
            a = BitOperations.RotateRight(a - roundKey[0], (int)u) ^ t;
        }

        block[0] = a;
        block[1] = b;
        block[2] = c;
        block[3] = d;
    }

    private void ValidateArgs(Span<uint> block, ReadOnlySpan<uint> roundKey)
    {
        if (block.Length != 4)
            throw new ArgumentException("Блок раунда RC6 должен содержать 4 слова", nameof(block));

        if (roundKey.Length != 2)
            throw new ArgumentException("Раундовый ключ RC6 должен содержать 2 слова", nameof(roundKey));
    }
}
