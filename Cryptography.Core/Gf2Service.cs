namespace Cryptography.Core;

public class Gf2Service
{
    public byte MultiplyUnchecked(byte a, byte b, byte mod)
    {
        int res = 0;
        int x = a;
        int y = b;
        while (y != 0)
        {
            if ((y & 1) != 0)
                res ^= x;

            bool hasHighBit = (x & 0x80) != 0;
            x = ((x << 1) ^ (hasHighBit ? mod : 0)) & 0xFF;
            y >>= 1;
        }
        return (byte)res;
    }
}
