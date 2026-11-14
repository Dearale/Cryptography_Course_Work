namespace Cryptography.Core;

public interface IRoundEncryptor<T>
{
    void Encrypt(Span<T> block, ReadOnlySpan<T> roundKey);
    void Decrypt(Span<T> block, ReadOnlySpan<T> roundKey);
}
