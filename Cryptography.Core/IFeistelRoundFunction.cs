namespace Cryptography.Core;

public interface IFeistelRoundFunction
{
    void Encrypt(ReadOnlySpan<byte> half, ReadOnlySpan<byte> roundKey, Span<byte> res);
}
