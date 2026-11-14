using System;
using System.Collections.Generic;
using System.Text;

namespace Cryptography.Core;

public enum CipherMode
{
    ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta
}

public enum PaddingMode
{
    Zeros, AnsiX923, PKCS7, ISO10126
}