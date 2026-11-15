namespace Cryptography.Core;

public class Magenta : FeistelNetwork
{
    public Magenta()
        : base(new MagentaKeyExpansion(), new MagentaRoundEncryptor(), 16)
    {
    }
}
