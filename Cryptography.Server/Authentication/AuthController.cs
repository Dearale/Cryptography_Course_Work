using System.Security.Claims;
using System.Security.Cryptography;
using Cryptography.Contracts;
using Cryptography.Server.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;

namespace Cryptography.Server.Authentication;

[ApiController]
[Route("api/auth")]
[Authorize]
[RequestSizeLimit(4096)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public class AuthController : ControllerBase
{
    private UserStore users;
    private IPasswordHasher<User> hasher;
    private AuthOptions options;
    private TimeProvider clock;

    public AuthController(UserStore users, IPasswordHasher<User> hasher, AuthOptions options, TimeProvider clock)
    {
        this.users = users;
        this.hasher = hasher;
        this.options = options;
        this.clock = clock;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    public async Task<ActionResult<UserResponse>> Register(RegisterRequest request, CancellationToken cancellationToken)
    {
        User user = new() { Id = Guid.NewGuid(), Login = request.Login };
        user.PasswordHash = hasher.HashPassword(user, request.Password);

        if (!await users.CreateUserAsync(user, cancellationToken))
            return Conflict(new ProblemDetails { Status = 409, Title = "Логин уже занят" });

        return StatusCode(StatusCodes.Status201Created, new UserResponse(user.Id, user.Login));
    }

    [HttpPost("login")]
    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    public async Task<ActionResult<LoginResponse>> Login(LoginRequest request, CancellationToken cancellationToken)
    {
        User? user = await users.FindUserAsync(request.Login, cancellationToken);
        if (user == null)
        {
            hasher.HashPassword(new User(), request.Password);
            return Unauthorized(new ProblemDetails { Status = 401, Title = "Неверный логин или пароль" });
        }

        PasswordVerificationResult verificationRes = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
        if (verificationRes == PasswordVerificationResult.Failed)
            return Unauthorized(new ProblemDetails { Status = 401, Title = "Неверный логин или пароль" });

        if (verificationRes == PasswordVerificationResult.SuccessRehashNeeded)
            await users.UpdatePasswordHashAsync(user.Id, hasher.HashPassword(user, request.Password), cancellationToken);

        string token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        long now = clock.GetUtcNow().ToUnixTimeSeconds();
        long expiresAt = clock.GetUtcNow().AddHours(options.SessionHours).ToUnixTimeSeconds();
        await users.CreateSessionAsync(BearerAuthenticationHandler.HashToken(token), user.Id, expiresAt, now, cancellationToken);

        return new LoginResponse(token, DateTimeOffset.FromUnixTimeSeconds(expiresAt), new UserResponse(user.Id, user.Login));
    }

    [HttpGet("me")]
    public UserResponse Me() => new UserResponse(Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!), User.Identity!.Name!);

    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        await users.DeleteSessionAsync(User.FindFirstValue(ClaimTypes.Sid)!, cancellationToken);
        return NoContent();
    }
}
