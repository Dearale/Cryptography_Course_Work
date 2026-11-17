using System.ComponentModel.DataAnnotations;
using System.Threading.RateLimiting;
using Cryptography.Server.Authentication;
using Cryptography.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Cryptography.Server;

public class Program
{
    public static async Task Main(string[] args)
    {
        await using WebApplication app = await CreateAppAsync(args);
        await app.RunAsync();
    }

    public static async Task<WebApplication> CreateAppAsync(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ApplicationName = typeof(Program).Assembly.GetName().Name
        });

        configure?.Invoke(builder);
        AuthOptions options = builder.Configuration.GetSection("Authentication").Get<AuthOptions>() ?? new AuthOptions();
        Validator.ValidateObject(options, new ValidationContext(options), true);

        builder.Services.AddSingleton(options);
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<UserStore>();
        builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
        builder.Services.Configure<PasswordHasherOptions>(hash => hash.IterationCount = options.PasswordIterations);
        builder.Services.AddAuthentication(BearerAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, BearerAuthenticationHandler>(BearerAuthenticationHandler.SchemeName, null);
        builder.Services.AddAuthorization();
        builder.Services.AddControllers();
        builder.Services.AddProblemDetails();
        builder.Services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = options.PermitLimit,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                }));
        });

        WebApplication app = builder.Build();
        app.UseExceptionHandler();
        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapControllers();
        await app.Services.GetRequiredService<UserStore>().InitializeAsync();

        return app;
    }
}
