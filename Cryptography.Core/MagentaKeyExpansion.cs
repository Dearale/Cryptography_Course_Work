namespace Cryptography.Core;

public class MagentaKeyExpansion : IKeyExpansion<byte[]>
{
    public byte[][] ExpandKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length is not (16 or 24 or 32))
            throw new ArgumentException("Ключ MAGENTA должен содержать 16, 24 или 32 байта", nameof(key));

        int[] roundOrder = key.Length switch
        {
            16 => [0, 0, 1, 1, 0, 0],
            24 => [0, 1, 2, 2, 1, 0],
            _ => [0, 1, 2, 3, 3, 2, 1, 0]
        };

        byte[][] res = new byte[roundOrder.Length][];
        for (int i = 0; i < roundOrder.Length; i++)
            res[i] = key.AsSpan(roundOrder[i] * 8, 8).ToArray();
        return res;
    }
}
