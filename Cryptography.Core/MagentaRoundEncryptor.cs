namespace Cryptography.Core;

public class MagentaRoundEncryptor : IFeistelRoundFunction
{
    private const byte FieldMod = 0x65;
    private static readonly byte[] substitution = CreateSubstitution();

    public void Encrypt(ReadOnlySpan<byte> half, ReadOnlySpan<byte> roundKey, Span<byte> res)
    {
        if (half.Length != 8)
            throw new ArgumentException("Половина блока MAGENTA должна содержать 8 байт", nameof(half));
        if (roundKey.Length != 8)
            throw new ArgumentException("Раундовый ключ MAGENTA должен содержать 8 байт", nameof(roundKey));
        if (res.Length != 8)
            throw new ArgumentException("Результат раундовой функции MAGENTA должен содержать 8 байт", nameof(res));

        Span<byte> input = stackalloc byte[16];
        half.CopyTo(input);
        roundKey.CopyTo(input[8..]);

        Span<byte> state = stackalloc byte[16];
        Span<byte> mixed = stackalloc byte[16];
        input.CopyTo(state);

        for (int stage = 0; stage < 3; stage++) // C
        {
            for (int layer = 0; layer < 4; layer++) // T
            {
                for (int i = 0; i < 8; i++) // П
                { // PE
                    mixed[2 * i] = substitution[state[i] ^ substitution[state[i + 8]]]; // A
                    mixed[2 * i + 1] = substitution[state[i + 8] ^ substitution[state[i]]]; // A
                }
                mixed.CopyTo(state);
            }

            if (stage < 2)
            {
                for (int i = 0; i < 8; i++) // W xor S
                {
                    mixed[i] = (byte)(input[i] ^ state[2 * i]);
                    mixed[i + 8] = (byte)(input[i + 8] ^ state[2 * i + 1]);
                }
                mixed.CopyTo(state);
            }
        }

        for (int i = 0; i < 8; i++) // First8(S)
            res[i] = state[2 * i];
    }

    private static byte[] CreateSubstitution()
    {
        Gf2Service gf = new Gf2Service();
        byte[] res = new byte[256];
        byte val = 1;
        for (int i = 0; i < 255; i++)
        {
            res[i] = val;
            val = gf.MultiplyUnchecked(val, 2, FieldMod);
        }
        return res;
    }
}
