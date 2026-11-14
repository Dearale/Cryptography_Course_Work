using System;
using System.Collections.Generic;
using System.Text;

namespace Cryptography.Core;

public interface ISymmetricCipher
{
    int BlockSize { get; }

    void SetKey(byte[] key);
    byte[] Encrypt(byte[] block);
    byte[] Decrypt(byte[] block);
}