namespace Cryptography.Core;

public static class Utils
{
    public static byte[] Xor(byte[] first, byte[] second)
    {
        if (first.Length != second.Length)
            throw new ArgumentException("Размеры массивов должны совпадать");

        byte[] res = new byte[first.Length];
        for (int i = 0; i < res.Length; i++)
            res[i] = (byte)(first[i] ^ second[i]);
        return res;
    }
}
