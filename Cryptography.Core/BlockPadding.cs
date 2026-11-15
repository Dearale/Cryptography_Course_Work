using System.Security.Cryptography;

namespace Cryptography.Core;

public static class BlockPadding
{
    public static byte[] Apply(byte[] data, int blockSize, PaddingMode padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateParams(blockSize, padding);
        int remainder = data.Length % blockSize;
        int paddingSize;

        if (padding == PaddingMode.Zeros)
            paddingSize = remainder == 0 ? 0 : blockSize - remainder;
        else
            paddingSize = remainder == 0 ? blockSize : blockSize - remainder;

        byte[] res = new byte[data.Length + paddingSize];
        Array.Copy(data, res, data.Length);
        if (paddingSize == 0)
            return res;

        switch (padding)
        {
            case PaddingMode.Zeros:
                break;
            case PaddingMode.AnsiX923:
                res[^1] = (byte)paddingSize;
                break;
            case PaddingMode.PKCS7:
                for (int i = data.Length; i < res.Length; i++)
                    res[i] = (byte)paddingSize;
                break;
            case PaddingMode.ISO10126:
                if (paddingSize > 1)
                    RandomNumberGenerator.Fill(res.AsSpan(data.Length, paddingSize - 1));
                res[^1] = (byte)paddingSize;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(padding));
        }
        return res;
    }

    public static byte[] Remove(byte[] data, int blockSize, PaddingMode padding, int? originalLength = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateParams(blockSize, padding);
        if (data.Length % blockSize != 0)
            throw new ArgumentException("Размер данных должен быть кратен размеру блока", nameof(data));
        if (data.Length == 0 && padding != PaddingMode.Zeros)
            throw new CryptographicException("Данные не содержат дополнения");

        switch (padding)
        {
            case PaddingMode.Zeros:
                return RemoveZerosPadding(data, blockSize, originalLength);
            case PaddingMode.AnsiX923:
                return RemoveAnsiX923Padding(data, blockSize, originalLength);
            case PaddingMode.PKCS7:
                return RemovePKCS7Padding(data, blockSize, originalLength);
            case PaddingMode.ISO10126:
                return RemoveISO10126Padding(data, blockSize, originalLength);
            default:
                throw new ArgumentOutOfRangeException(nameof(padding));
        }
    }

    private static byte[] RemoveZerosPadding(byte[] data, int blockSize, int? originalLength)
    {
        if (originalLength == null)
            throw new ArgumentException("Для Zeros необходима исходная длина данных", nameof(originalLength));
        if (originalLength < 0 || originalLength > data.Length)
            throw new ArgumentOutOfRangeException(nameof(originalLength));

        int paddingSize = data.Length - originalLength.Value;
        if (paddingSize >= blockSize)
            throw new CryptographicException("Некорректный размер дополнения Zeros");
        for (int i = originalLength.Value; i < data.Length; i++)
        {
            if (data[i] != 0)
                throw new CryptographicException("Некорректное дополнение Zeros");
        }
        return RemoveLastBytes(data, paddingSize);
    }

    private static byte[] RemoveAnsiX923Padding(byte[] data, int blockSize, int? originalLength)
    {
        int paddingSize = data[^1];
        ValidatePaddingSize(data, paddingSize, blockSize, originalLength);

        for (int i = data.Length - paddingSize; i < data.Length - 1; i++)
        {
            if (data[i] != 0)
                throw new CryptographicException("Некорректная ANSI X.923 набивка.");
        }
        return RemoveLastBytes(data, paddingSize);
    }

    private static byte[] RemovePKCS7Padding(byte[] data, int blockSize, int? originalLength)
    {
        int paddingSize = data[^1];
        ValidatePaddingSize(data, paddingSize, blockSize, originalLength);

        for (int i = data.Length - paddingSize; i < data.Length; i++)
        {
            if (data[i] != paddingSize)
                throw new CryptographicException("Некорректная PKCS7 набивка");
        }
        return RemoveLastBytes(data, paddingSize);
    }

    private static byte[] RemoveISO10126Padding(byte[] data, int blockSize, int? originalLength)
    {
        int paddingSize = data[^1];
        ValidatePaddingSize(data, paddingSize, blockSize, originalLength);
        return RemoveLastBytes(data, paddingSize);
    }

    private static void ValidatePaddingSize(byte[] data, int paddingSize, int blockSize, int? originalLength)
    {
        if (paddingSize <= 0 || paddingSize > blockSize || paddingSize > data.Length)
            throw new CryptographicException("Некорректный размер дополнения");
        if (originalLength != null && originalLength != data.Length - paddingSize)
            throw new CryptographicException("Исходная длина не соответствует дополнению");
    }

    private static byte[] RemoveLastBytes(byte[] data, int count)
    {
        int resLen = data.Length - count;
        byte[] res = new byte[resLen];
        Array.Copy(data, res, resLen);
        return res;
    }

    private static void ValidateParams(int blockSize, PaddingMode padding)
    {
        if (blockSize is < 1 or > 255)
            throw new ArgumentOutOfRangeException(nameof(blockSize));
    }
}
