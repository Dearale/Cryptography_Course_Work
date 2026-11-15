using Cryptography.Core;
using CryptographicException = System.Security.Cryptography.CryptographicException;

namespace Cryptography.Tests;

public class SymmetricCipherFileTests
{
    private string directory = null!;
    private string InputPath => Path.Combine(directory, "input.bin");
    private string EncryptedPath => Path.Combine(directory, "encrypted.bin");
    private string DecryptedPath => Path.Combine(directory, "decrypted.bin");

    [SetUp]
    public void SetUp()
    {
        directory = Directory.CreateTempSubdirectory("CourseCipherTests-").FullName;
    }

    [TearDown]
    public void TearDown()
    {
        File.Delete(InputPath);
        File.Delete(EncryptedPath);
        File.Delete(DecryptedPath);
        Directory.Delete(directory);
    }

    [Test]
    public async Task FilesMatchArraysAcrossBufferBoundaries(
        [Values] CipherMode mode, [Values] PaddingMode padding,
        [Values(0, 65520, 65521, 65536, 131049)] int len)
    {
        SymmetricCipherContext context = SymmetricCipherContextTests.CreateContext(new TestBlockCipher(24), mode, padding);
        byte[] plain = SymmetricCipherContextTests.CreateData(len);
        await File.WriteAllBytesAsync(InputPath, plain);
        byte[] encrypted = await context.EncryptAsync(plain);
        await context.EncryptAsync(InputPath, EncryptedPath);
        byte[] fileEncrypted = await File.ReadAllBytesAsync(EncryptedPath);

        Assert.That(fileEncrypted.Length, Is.EqualTo(encrypted.Length));
        int deterministicLength = padding == PaddingMode.ISO10126 ? encrypted.Length - 24 : encrypted.Length;
        Assert.That(fileEncrypted.AsSpan(0, deterministicLength).ToArray(),
            Is.EqualTo(encrypted.AsSpan(0, deterministicLength).ToArray()));
        Assert.That(await context.DecryptAsync(fileEncrypted, len), Is.EqualTo(plain));
        await context.DecryptAsync(EncryptedPath, DecryptedPath, len);
        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(plain));
        await File.WriteAllBytesAsync(EncryptedPath, encrypted);
        await context.DecryptAsync(EncryptedPath, DecryptedPath, len);
        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(plain));
    }

    [Test]
    public async Task FilesWorkWithCourseCiphers([Values] CipherMode mode, [Values(false, true)] bool useMagenta)
    {
        ISymmetricCipher cipher = useMagenta ? new Magenta() : new Rc6();
        SymmetricCipherContext context = SymmetricCipherContextTests.CreateContext(cipher, mode, PaddingMode.PKCS7);
        byte[] plain = SymmetricCipherContextTests.CreateData(65537);
        await File.WriteAllBytesAsync(InputPath, plain);
        byte[] expected = await context.EncryptAsync(plain);
        await context.EncryptAsync(InputPath, EncryptedPath);
        Assert.That(await File.ReadAllBytesAsync(EncryptedPath), Is.EqualTo(expected));
        await context.DecryptAsync(EncryptedPath, DecryptedPath);
        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(plain));
    }

    [Test]
    public async Task InvalidCiphertextDoesNotOverwriteOutput()
    {
        SymmetricCipherContext context = SymmetricCipherContextTests.CreateContext(new Rc6(), CipherMode.CBC, PaddingMode.PKCS7);
        byte[] original = [1, 2, 3];
        await File.WriteAllBytesAsync(EncryptedPath, new byte[17]);
        await File.WriteAllBytesAsync(DecryptedPath, original);
        Assert.ThrowsAsync<ArgumentException>(() => context.DecryptAsync(EncryptedPath, DecryptedPath));
        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(original));
    }

    [Test]
    public async Task RejectsSameInputAndOutput()
    {
        SymmetricCipherContext context = SymmetricCipherContextTests.CreateContext(new Rc6(), CipherMode.ECB, PaddingMode.PKCS7);
        byte[] plain = SymmetricCipherContextTests.CreateData(17);
        await File.WriteAllBytesAsync(InputPath, plain);
        Assert.ThrowsAsync<ArgumentException>(() => context.EncryptAsync(InputPath, InputPath));
        Assert.That(await File.ReadAllBytesAsync(InputPath), Is.EqualTo(plain));
    }

    [TestCase(PaddingMode.AnsiX923)]
    [TestCase(PaddingMode.PKCS7)]
    [TestCase(PaddingMode.ISO10126)]
    public async Task RejectsInvalidFinalPadding(PaddingMode padding)
    {
        TestBlockCipher cipher = new TestBlockCipher(16);
        SymmetricCipherContext context = SymmetricCipherContextTests.CreateContext(cipher, CipherMode.ECB, padding);
        byte[] encrypted = await context.EncryptAsync(SymmetricCipherContextTests.CreateData(65537));
        byte[] tail = cipher.Decrypt(encrypted[^16..]);
        tail[^1] = 0;
        cipher.Encrypt(tail).CopyTo(encrypted, encrypted.Length - 16);
        await File.WriteAllBytesAsync(EncryptedPath, encrypted);
        Assert.ThrowsAsync<CryptographicException>(() => context.DecryptAsync(EncryptedPath, DecryptedPath));
    }

    [Test]
    public async Task ReportsProgressAndAllowsCancellation()
    {
        SymmetricCipherContext context = SymmetricCipherContextTests.CreateContext(new Rc6(), CipherMode.CBC, PaddingMode.PKCS7);
        await File.WriteAllBytesAsync(InputPath, SymmetricCipherContextTests.CreateData(131089));
        CaptureProgress progress = new CaptureProgress();
        await context.EncryptAsync(InputPath, EncryptedPath, progress: progress);
        Assert.That(progress.Values.Count, Is.GreaterThan(1));
        Assert.That(progress.Values, Is.Ordered);
        Assert.That(progress.Values[^1], Is.EqualTo(1));

        using CancellationTokenSource cancellation = new CancellationTokenSource();
        CaptureProgress cancelProgress = new CaptureProgress { OnReport = cancellation.Cancel };
        Assert.That(async () => await context.EncryptAsync(InputPath, EncryptedPath, cancellation.Token, cancelProgress),
            Throws.InstanceOf<OperationCanceledException>());
        Assert.That(cancelProgress.Values, Has.Count.EqualTo(1));
        Assert.That(cancelProgress.Values[0], Is.LessThan(1));
    }

    private class CaptureProgress : IProgress<double>
    {
        public List<double> Values { get; } = [];
        public Action? OnReport { get; set; }

        public void Report(double value)
        {
            Values.Add(value);
            OnReport?.Invoke();
        }
    }
}
