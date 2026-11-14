namespace Cryptography.Core;

public interface IKeyExpansion<T>
{
    T[] ExpandKey(byte[] key);
}
