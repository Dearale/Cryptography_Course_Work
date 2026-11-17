using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cryptography.Contracts;
using Cryptography.Server.Authentication;
using Cryptography.Server.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ServerProgram = Cryptography.Server.Program;

namespace Cryptography.Tests;

public class AuthApiTests
{
    private X509Certificate2 certificate = null!;
    private WebApplication app = null!;
    private HttpClient client = null!;
    private string directory = null!;
    private TestClock clock = null!;
    private string DatabasePath => Path.Combine(directory, "server.db");

    [OneTimeSetUp]
    public void CreateCertificate()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        SubjectAlternativeNameBuilder names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using X509Certificate2 temporary = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        certificate = X509CertificateLoader.LoadPkcs12(temporary.Export(X509ContentType.Pfx), null);
    }

    [SetUp]
    public async Task StartServer()
    {
        directory = Directory.CreateTempSubdirectory("CourseAuthTests-").FullName;
        clock = new TestClock();
        await StartApp();
    }

    private async Task StartApp(int permitLimit = 1000)
    {
        app = await ServerProgram.CreateAppAsync([], builder =>
        {
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Database:Path"] = DatabasePath,
                ["Authentication:SessionHours"] = "1",
                ["Authentication:PasswordIterations"] = "100000",
                ["Authentication:PermitLimit"] = permitLimit.ToString()
            });
            builder.Services.AddSingleton<TimeProvider>(clock);
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, 0, endpoint => endpoint.UseHttps(certificate)));
        });
        await app.StartAsync();
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        client = new HttpClient(new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert?.Thumbprint == certificate.Thumbprint
        }) { BaseAddress = new Uri(address) };
    }

    private async Task StopApp()
    {
        client.Dispose();
        await app.StopAsync();
        await app.DisposeAsync();
    }

    [TearDown]
    public async Task StopServer()
    {
        await StopApp();
        SqliteConnection.ClearAllPools();
        foreach (string suffix in new[] { "", "-wal", "-shm" })
            File.Delete(DatabasePath + suffix);
        Directory.Delete(directory);
    }

    [OneTimeTearDown]
    public void DisposeCertificate() => certificate.Dispose();

    [Test]
    public async Task RegisterLoginAndGetCurrentUser()
    {
        UserResponse user = await Register();
        LoginResponse session = await Login("ALICE");
        Assert.That(session.User, Is.EqualTo(user));
        Assert.That(session.AccessToken, Has.Length.EqualTo(43));
        Assert.That(session.ExpiresAt, Is.EqualTo(clock.GetUtcNow().AddHours(1)));
        using HttpResponseMessage response = await GetMe(session.AccessToken);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(response.Headers.CacheControl?.NoStore, Is.True);
        Assert.That(await response.Content.ReadFromJsonAsync<UserResponse>(), Is.EqualTo(user));
        string json = await response.Content.ReadAsStringAsync();
        Assert.That(json, Does.Not.Contain("password").IgnoreCase);
    }

    [Test]
    public async Task ConcurrentRegistrationsEnforceUniqueLogin()
    {
        Task<HttpResponseMessage>[] requests = new[] { "Alice", "alice", "ALICE" }
            .Select(login => client.PostAsJsonAsync("api/auth/register", new RegisterRequest { Login = login, Password = "password12345" }))
            .ToArray();
        HttpResponseMessage[] responses = await Task.WhenAll(requests);
        try
        {
            Assert.That(responses.Count(response => response.StatusCode == HttpStatusCode.Created), Is.EqualTo(1));
            Assert.That(responses.Count(response => response.StatusCode == HttpStatusCode.Conflict), Is.EqualTo(2));
        }
        finally
        {
            foreach (HttpResponseMessage response in responses)
                response.Dispose();
        }
    }

    [TestCase("ab", "password12345")]
    [TestCase("имя", "password12345")]
    [TestCase("alice bob", "password12345")]
    [TestCase("alice'--", "password12345")]
    [TestCase("Alice", "short")]
    [TestCase("Alice", "")]
    [TestCase(null, "password12345")]
    [TestCase("Alice", null)]
    public async Task RejectInvalidRegistration(string? login, string? password)
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync("api/auth/register", new { Login = login, Password = password });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [TestCase(2, 12, false)]
    [TestCase(3, 11, false)]
    [TestCase(3, 12, true)]
    [TestCase(32, 128, true)]
    [TestCase(33, 128, false)]
    [TestCase(32, 129, false)]
    public async Task ValidateCredentialLengthBoundaries(int loginLength, int passwordLength, bool valid)
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync("api/auth/register", new RegisterRequest
        {
            Login = new string('a', loginLength),
            Password = new string('x', passwordLength)
        });
        Assert.That(response.StatusCode, Is.EqualTo(valid ? HttpStatusCode.Created : HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task UnknownUserAndWrongPasswordHaveSameError()
    {
        await Register();
        using HttpResponseMessage unknown = await client.PostAsJsonAsync("api/auth/login",
            new LoginRequest { Login = "unknown", Password = "password12345" });
        using HttpResponseMessage wrong = await client.PostAsJsonAsync("api/auth/login",
            new LoginRequest { Login = "Alice", Password = "Password12345" });
        Assert.That(unknown.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(wrong.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        ProblemDetails? unknownError = await unknown.Content.ReadFromJsonAsync<ProblemDetails>();
        ProblemDetails? wrongError = await wrong.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.That(unknownError!.Title, Is.EqualTo(wrongError!.Title));
    }

    [TestCase(null)]
    [TestCase("invalid-token")]
    public async Task RejectMissingOrInvalidToken(string? token)
    {
        using HttpResponseMessage response = await GetMe(token);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(response.Headers.WwwAuthenticate.Single().Scheme, Is.EqualTo("Bearer"));
    }

    [Test]
    public async Task LogoutRevokesOnlyCurrentSession()
    {
        await Register();
        LoginResponse first = await Login();
        LoginResponse second = await Login();
        Assert.That(first.AccessToken, Is.Not.EqualTo(second.AccessToken));
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "api/auth/logout");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", first.AccessToken);
        using HttpResponseMessage logout = await client.SendAsync(request);
        Assert.That(logout.StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
        using HttpResponseMessage revoked = await GetMe(first.AccessToken);
        using HttpResponseMessage active = await GetMe(second.AccessToken);
        Assert.That(revoked.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(active.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task SessionExpiresAtExactBoundary()
    {
        await Register();
        LoginResponse session = await Login();
        clock.UtcNow = session.ExpiresAt.AddSeconds(-1);
        using HttpResponseMessage valid = await GetMe(session.AccessToken);
        Assert.That(valid.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        clock.UtcNow = session.ExpiresAt;
        using HttpResponseMessage expired = await GetMe(session.AccessToken);
        Assert.That(expired.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task UsersAndSessionsSurviveRestart()
    {
        await Register();
        LoginResponse session = await Login();
        await StopApp();
        await StartApp();
        using HttpResponseMessage response = await GetMe(session.AccessToken);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await Login()).User, Is.EqualTo(session.User));
    }

    [Test]
    public async Task DatabaseStoresSaltedPasswordHashesAndTokenHashes()
    {
        await Register();
        await Register("Bob");
        LoginResponse session = await Login();
        UserStore users = app.Services.GetRequiredService<UserStore>();
        User alice = (await users.FindUserAsync("Alice", default))!;
        User bob = (await users.FindUserAsync("Bob", default))!;
        Assert.That(alice.PasswordHash, Is.Not.EqualTo("password12345"));
        Assert.That(alice.PasswordHash, Is.Not.EqualTo(bob.PasswordHash));
        PasswordHasher<User> hasher = new PasswordHasher<User>();
        Assert.That(hasher.VerifyHashedPassword(alice, alice.PasswordHash, "password12345"), Is.Not.EqualTo(PasswordVerificationResult.Failed));
        await using SqliteConnection connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = DatabasePath }.ToString());
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT TokenHash FROM Sessions;";
        string stored = (string)(await command.ExecuteScalarAsync())!;
        Assert.That(stored, Is.Not.EqualTo(session.AccessToken));
        Assert.That(stored, Is.EqualTo(BearerAuthenticationHandler.HashToken(session.AccessToken)));
    }

    [Test]
    public async Task LoginUpgradesOldPasswordHash()
    {
        User user = new User { Id = Guid.NewGuid(), Login = "Alice" };
        PasswordHasher<User> oldHasher = new PasswordHasher<User>(Microsoft.Extensions.Options.Options.Create(
            new PasswordHasherOptions { IterationCount = 10_000 }));
        user.PasswordHash = oldHasher.HashPassword(user, "password12345");
        UserStore users = app.Services.GetRequiredService<UserStore>();
        await users.CreateUserAsync(user, default);
        await Login();
        User updated = (await users.FindUserAsync("Alice", default))!;
        Assert.That(updated.PasswordHash, Is.Not.EqualTo(user.PasswordHash));
        Assert.That(new PasswordHasher<User>().VerifyHashedPassword(updated, updated.PasswordHash, "password12345"),
            Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public async Task AuthenticationRequestsAreRateLimited()
    {
        await StopApp();
        await StartApp(2);
        using HttpResponseMessage first = await client.PostAsJsonAsync("api/auth/login", new LoginRequest { Login = "Alice", Password = "wrong" });
        using HttpResponseMessage second = await client.PostAsJsonAsync("api/auth/register", new RegisterRequest { Login = "Bob", Password = "password12345" });
        using HttpResponseMessage third = await client.PostAsJsonAsync("api/auth/login", new LoginRequest { Login = "Alice", Password = "wrong" });
        Assert.That(first.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(second.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        Assert.That(third.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));
    }

    private async Task<UserResponse> Register(string login = "Alice")
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync("api/auth/register",
            new RegisterRequest { Login = login, Password = "password12345" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        return (await response.Content.ReadFromJsonAsync<UserResponse>())!;
    }

    private async Task<LoginResponse> Login(string login = "Alice")
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync("api/auth/login",
            new LoginRequest { Login = login, Password = "password12345" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        return (await response.Content.ReadFromJsonAsync<LoginResponse>())!;
    }

    private async Task<HttpResponseMessage> GetMe(string? token)
    {
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "api/auth/me");
        if (token != null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }

    public class TestClock : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
