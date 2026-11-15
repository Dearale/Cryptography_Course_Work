using System.Numerics;
using System.Security.Cryptography;

namespace Cryptography.Core;

public class SymmetricCipherContext
{
    private ISymmetricCipher cipher;
    private CipherMode mode;
    private PaddingMode padding;
    private byte[]? iv;
    private object[] modeArgs;

    private const int ByteMask = (1 << 8) - 1;
    private const int FileBufferSize = 64 * 1024;

    private class OperationState
    {
        public byte[] previous;
        public byte[] previousPlain;
        public long blockIndex;
        public CancellationToken cancellationToken;
        public ParallelOptions options;

        public OperationState(byte[]? iv, int blockSize, CancellationToken cancellationToken)
        {
            previous = iv == null ? new byte[blockSize] : (byte[])iv.Clone();
            previousPlain = new byte[blockSize];
            this.cancellationToken = cancellationToken;
            options = new ParallelOptions { CancellationToken = cancellationToken };
        }
    }

    public SymmetricCipherContext(ISymmetricCipher cipher, byte[] key, CipherMode mode,
        PaddingMode padding, byte[]? iv = null, params object[] modeArgs)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        ArgumentNullException.ThrowIfNull(key);

        this.cipher = cipher;
        this.mode = mode;
        this.padding = padding;
        this.iv = iv == null ? null : (byte[])iv.Clone();
        this.modeArgs = modeArgs == null ? [] : (object[])modeArgs.Clone();
        ValidateParams();
        cipher.SetKey(key);
    }

    private void ValidateParams()
    {
        if (cipher.BlockSize is < 1 or > 255)
            throw new ArgumentException("Размер блока должен быть от 1 до 255 байт");

        if (mode != CipherMode.ECB && iv == null)
            throw new ArgumentException("Для данного режима необходим IV", nameof(iv));

        if (iv != null && iv.Length != cipher.BlockSize)
            throw new ArgumentException($"Размер IV должен быть равен {cipher.BlockSize} байт", nameof(iv));

        if (mode == CipherMode.RandomDelta && (modeArgs.Length == 0 || modeArgs[0] is not BigInteger delta ||
            delta <= 0 || delta >= BigInteger.One << (cipher.BlockSize * 8)))
            throw new ArgumentOutOfRangeException(nameof(modeArgs), "Для RandomDelta необходим ненулевой BigInteger delta размером не больше блока");
    }

    public Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        return Task.Run(() => Encrypt(data, cancellationToken), cancellationToken);
    }

    public Task<byte[]> DecryptAsync(byte[] data, int? originalLength = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateCiphertext(data.Length, originalLength);
        return Task.Run(() => Decrypt(data, originalLength, cancellationToken), cancellationToken);
    }

    public async Task EncryptAsync(string inputPath, string outputPath,
        CancellationToken cancellationToken = default, IProgress<double>? progress = null)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ValidatePaths(inputPath, outputPath);
        await using FileStream input = OpenInputFile(inputPath);
        await using FileStream output = OpenOutputFile(outputPath);

        byte[] buffer = new byte[GetAlignedFileBufferSize()];
        OperationState state = new(iv, cipher.BlockSize, cancellationToken);

        while (true)
        {
            int bytesRead = await input.ReadAtLeastAsync(buffer, buffer.Length, false, cancellationToken);
            bool isFinal = bytesRead < buffer.Length;

            byte[] data = isFinal ? ApplyPadding(buffer[..bytesRead]) : buffer;
            byte[] encrypted = await Task.Run(() => TransformBlocks(data, false, state), cancellationToken);

            await output.WriteAsync(encrypted, cancellationToken);
            progress?.Report(input.Length == 0 ? 1 : (double)input.Position / input.Length);
            if (isFinal)
                break;
        }
    }

    public async Task DecryptAsync(string inputPath, string outputPath, long? originalLength = null,
        CancellationToken cancellationToken = default, IProgress<double>? progress = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidatePaths(inputPath, outputPath);
        await using FileStream input = OpenInputFile(inputPath);
        ValidateCiphertext(input.Length, originalLength);
        await using FileStream output = OpenOutputFile(outputPath);

        byte[] buffer = new byte[GetAlignedFileBufferSize()];
        OperationState state = new(iv, cipher.BlockSize, cancellationToken);

        while (true)
        {
            int bytesRead = await input.ReadAtLeastAsync(buffer, buffer.Length, false, cancellationToken);
            if (bytesRead == 0)
                break;

            byte[] data = bytesRead == buffer.Length ? buffer : buffer[..bytesRead];
            byte[] decrypted = await Task.Run(() => TransformBlocks(data, true, state), cancellationToken);

            if (input.Position == input.Length)
            {
                int? tailLength = originalLength == null ? null : (int)(originalLength - output.Position);
                decrypted = RemovePadding(decrypted, tailLength);
            }

            await output.WriteAsync(decrypted, cancellationToken);
            progress?.Report((double)input.Position / input.Length);
        }
        if (input.Length == 0)
            progress?.Report(1);
    }

    public static byte[] GenerateIV(int blockSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(blockSize);
        return RandomNumberGenerator.GetBytes(blockSize);
    }

    private static void ValidatePaths(string inputPath, string outputPath)
    {
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        if (string.Equals(Path.GetFullPath(inputPath), Path.GetFullPath(outputPath), comparison))
            throw new ArgumentException("Входной и выходной файлы должны различаться", nameof(outputPath));
    }

    private void ValidateCiphertext(long len, long? originalLength)
    {
        if (len % cipher.BlockSize != 0)
            throw new ArgumentException("Размер зашифрованных данных должен быть кратен размеру блока");

        if (padding != PaddingMode.Zeros && len == 0)
            throw new CryptographicException("Зашифрованные данные не содержат дополнения");

        if (padding == PaddingMode.Zeros && originalLength == null)
            throw new ArgumentException("Для Zeros необходима исходная длина данных", nameof(originalLength));

        if (originalLength != null)
        {
            if (originalLength < 0 || originalLength > len)
                throw new ArgumentOutOfRangeException(nameof(originalLength));

            long count = len - originalLength.Value;
            if (padding == PaddingMode.Zeros 
                ? count >= cipher.BlockSize 
                : count < 1 || count > cipher.BlockSize)
                throw new CryptographicException("Исходная длина не соответствует размеру дополнения");
        }
    }

    private int GetAlignedFileBufferSize() =>
        Math.Max(cipher.BlockSize, FileBufferSize - FileBufferSize % cipher.BlockSize);

    private static FileStream OpenInputFile(string path) => new FileStream(
        path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferSize,
        FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static FileStream OpenOutputFile(string path) => new FileStream(
        path, FileMode.Create, FileAccess.Write, FileShare.None, FileBufferSize,
        FileOptions.Asynchronous | FileOptions.SequentialScan);

    private byte[] Encrypt(byte[] data, CancellationToken cancellationToken)
    {
        byte[] paddedData = ApplyPadding(data);
        return TransformBlocks(paddedData, false, new OperationState(iv, cipher.BlockSize, cancellationToken));
    }

    private byte[] Decrypt(byte[] data, int? originalLength, CancellationToken cancellationToken)
    {
        byte[] decrypted = TransformBlocks(data, true, new OperationState(iv, cipher.BlockSize, cancellationToken));
        return RemovePadding(decrypted, originalLength);
    }

    private byte[] TransformBlocks(byte[] data, bool decrypt, OperationState state)
    {
        state.cancellationToken.ThrowIfCancellationRequested();
        byte[] result = mode switch
        {
            CipherMode.ECB => decrypt ? DecryptECB(data, state) : EncryptECB(data, state),
            CipherMode.CBC => decrypt ? DecryptCBC(data, state) : EncryptCBC(data, state),
            CipherMode.PCBC => decrypt ? DecryptPCBC(data, state) : EncryptPCBC(data, state),
            CipherMode.CFB => decrypt ? DecryptCFB(data, state) : EncryptCFB(data, state),
            CipherMode.OFB => CryptOFB(data, state),
            CipherMode.CTR => CryptCTR(data, state),
            CipherMode.RandomDelta => CryptRandomDelta(data, state),

            _ => throw new ArgumentOutOfRangeException()
        };

        state.blockIndex += data.Length / cipher.BlockSize;
        return result;
    }

    private byte[] EncryptECB(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        int blockCount = data.Length / cipher.BlockSize;

        Parallel.For(0, blockCount, state.options, i =>
        {
            int offset = i * cipher.BlockSize;

            byte[] block = GetBlock(data, offset);

            byte[] encrypted = cipher.Encrypt(block);

            WriteBlock(res, encrypted, offset);
        });

        return res;
    }

    private byte[] DecryptECB(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        int blockCount = data.Length / cipher.BlockSize;

        Parallel.For(0, blockCount, state.options, i =>
        {
            int offset = i * cipher.BlockSize;

            byte[] block = GetBlock(data, offset);

            byte[] decrypted = cipher.Decrypt(block);

            WriteBlock(res, decrypted, offset);
        });

        return res;
    }

    private byte[] EncryptCBC(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        byte[] previous = state.previous;

        for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
        {
            state.cancellationToken.ThrowIfCancellationRequested();
            byte[] block = GetBlock(data, offset);
            byte[] xored = Utils.Xor(block, previous);
            byte[] encrypted = cipher.Encrypt(xored);

            WriteBlock(res, encrypted, offset);

            previous = encrypted;
        }

        state.previous = previous;
        return res;
    }

    private byte[] DecryptCBC(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        int blockCount = data.Length / cipher.BlockSize;

        Parallel.For(0, blockCount, state.options, blockIndex =>
        {
            int offset = blockIndex * cipher.BlockSize;

            byte[] encrypted = GetBlock(data, offset);

            byte[] decrypted = cipher.Decrypt(encrypted);

            byte[] block;
            if (blockIndex == 0)
            {
                block = Utils.Xor(decrypted, state.previous);
            } else
            {
                block = Utils.Xor(decrypted, GetBlock(data, offset - cipher.BlockSize));
            }

            WriteBlock(res, block, offset);
        });

        if (data.Length > 0)
            state.previous = GetBlock(data, data.Length - cipher.BlockSize);
        return res;
    }

    private byte[] EncryptPCBC(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        byte[] prevPlain = state.previousPlain;
        byte[] prevEncrypted = state.previous;

        for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
        {
            state.cancellationToken.ThrowIfCancellationRequested();
            byte[] plain = GetBlock(data, offset);

            byte[] xored = Utils.Xor(Utils.Xor(plain, prevPlain), prevEncrypted);

            byte[] encrypted = cipher.Encrypt(xored);

            WriteBlock(res, encrypted, offset);

            prevPlain = plain;
            prevEncrypted = encrypted;
        }

        state.previousPlain = prevPlain;
        state.previous = prevEncrypted;
        return res;
    }

    private byte[] DecryptPCBC(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        byte[] prevPlain = state.previousPlain;
        byte[] prevEncrypted = state.previous;

        for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
        {
            state.cancellationToken.ThrowIfCancellationRequested();
            byte[] encrypted = GetBlock(data, offset);
            byte[] decrypted = cipher.Decrypt(encrypted);

            byte[] plain = Utils.Xor(prevEncrypted, Utils.Xor(decrypted, prevPlain));

            WriteBlock(res, plain, offset);

            prevPlain = plain;
            prevEncrypted = encrypted;
        }

        state.previousPlain = prevPlain;
        state.previous = prevEncrypted;
        return res;
    }

    private byte[] EncryptCFB(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        byte[] prev = state.previous;

        for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
        {
            state.cancellationToken.ThrowIfCancellationRequested();
            byte[] prevEncrypted = cipher.Encrypt(prev);

            byte[] plain = GetBlock(data, offset);

            byte[] encrypted = Utils.Xor(plain, prevEncrypted);

            WriteBlock(res, encrypted, offset);

            prev = encrypted;
        }

        state.previous = prev;
        return res;
    }

    private byte[] DecryptCFB(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        int blockCount = data.Length / cipher.BlockSize;
        Parallel.For(0, blockCount, state.options, blockIndex =>
        {
            int offset = blockIndex * cipher.BlockSize;

            byte[] encrypted = GetBlock(data, offset);

            byte[] prev;
            if (blockIndex == 0)
            {
                prev = state.previous;
            } else
            {
                prev = GetBlock(data, offset - cipher.BlockSize);
            }

            byte[] prevEncrypted = cipher.Encrypt(prev);
            byte[] plain = Utils.Xor(prevEncrypted, encrypted);
            WriteBlock(res, plain, offset);
        });

        if (data.Length > 0)
            state.previous = GetBlock(data, data.Length - cipher.BlockSize);
        return res;
    }

    private byte[] CryptOFB(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        byte[] prevEncrypted = state.previous;

        for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
        {
            state.cancellationToken.ThrowIfCancellationRequested();
            prevEncrypted = cipher.Encrypt(prevEncrypted);

            byte[] block = GetBlock(data, offset);

            byte[] encrypted = Utils.Xor(block, prevEncrypted);

            WriteBlock(res, encrypted, offset);
        }

        state.previous = prevEncrypted;
        return res;
    }

    private byte[] CryptCTR(byte[] data, OperationState state)
    {
        byte[] res = new byte[data.Length];

        int blockCount = data.Length / cipher.BlockSize;

        Parallel.For(0, blockCount, state.options, blockIndex =>
        {
            int offset = blockIndex * cipher.BlockSize;

            byte[] counter = CreateCounter(state.blockIndex + blockIndex);
            byte[] counterEncrypted = cipher.Encrypt(counter);

            byte[] block = GetBlock(data, offset);
            byte[] output = Utils.Xor(block, counterEncrypted);

            WriteBlock(res, output, offset);
        });

        return res;
    }

    private byte[] CryptRandomDelta(byte[] data, OperationState state)
    {
        BigInteger delta = (BigInteger)modeArgs[0];
        BigInteger iv = new BigInteger(this.iv!, isUnsigned: true, isBigEndian: true);
        BigInteger mod = BigInteger.One << (cipher.BlockSize * 8);
        byte[] res = new byte[data.Length];
        int blockCount = data.Length / cipher.BlockSize;

        Parallel.For(0, blockCount, state.options, i =>
        {
            BigInteger counter = (iv + (state.blockIndex + i) * delta) % mod;
            byte[] block = new byte[cipher.BlockSize];
            counter.TryWriteBytes(block, out _, isUnsigned: true, isBigEndian: false);
            Array.Reverse(block);
            byte[] encrypted = cipher.Encrypt(block);
            int offset = i * cipher.BlockSize;
            for (int j = 0; j < cipher.BlockSize; j++)
                res[offset + j] = (byte)(data[offset + j] ^ encrypted[j]);
        });
        return res;
    }

    private byte[] CreateCounter(long blockIndex)
    {
        byte[] counter = (byte[])iv!.Clone();
        long carry = blockIndex;
        for (int i = counter.Length - 1; i >= 0 && carry > 0; i--)
        {
            long sum = counter[i] + (carry & ByteMask);
            counter[i] = (byte)(sum & ByteMask);
            carry = (carry >> 8) + (sum >> 8);
        }
        return counter;
    }

    private byte[] ApplyPadding(byte[] data) =>
        BlockPadding.Apply(data, cipher.BlockSize, padding);

    private byte[] RemovePadding(byte[] data, int? originalLength = null) =>
        BlockPadding.Remove(data, cipher.BlockSize, padding, originalLength);

    private byte[] GetBlock(byte[] data, int offset)
    {
        byte[] block = new byte[cipher.BlockSize];

        Array.Copy(data, offset, block, 0, cipher.BlockSize);

        return block;
    }

    private void WriteBlock(byte[] dest, byte[] block, int offset)
    {
        Array.Copy(block, 0, dest, offset, block.Length);
    }
}
