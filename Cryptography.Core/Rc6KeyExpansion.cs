using System.Buffers.Binary;
using System.Numerics;

namespace Cryptography.Core;

public class Rc6KeyExpansion : IKeyExpansion<uint>
{
    private const int Rounds = 20;
    private const uint InitialRoundKey = 0xB7E15163;
    private const uint RoundKeyStep = 0x9E3779B9;

    public uint[] ExpandKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length is not (16 or 24 or 32))
            throw new ArgumentException("Ключ RC6 должен содержать 16, 24 или 32 байта");

        uint[] keyWords = new uint[key.Length / 4];
        for (int i = 0; i < keyWords.Length; i++)
            keyWords[i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4));

        uint[] roundKeys = new uint[2 * Rounds + 4];
        roundKeys[0] = InitialRoundKey;

        unchecked
        {
            for (int k = 1; k < roundKeys.Length; k++)
                roundKeys[k] = roundKeys[k - 1] + RoundKeyStep;

            uint a = 0, b = 0;
            int i = 0, j = 0;
            int cnt = 3 * Math.Max(roundKeys.Length, keyWords.Length);

            for (int k = 0; k < cnt; k++)
            {
                a = roundKeys[i] = BitOperations.RotateLeft(roundKeys[i] + a + b, 3);
                b = keyWords[j] = BitOperations.RotateLeft(keyWords[j] + a + b, (int)(a + b));
                i = (i + 1) % roundKeys.Length;
                j = (j + 1) % keyWords.Length;
            }
        }

        return roundKeys;
    }
}
