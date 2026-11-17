using System.ComponentModel.DataAnnotations;

namespace Cryptography.Contracts;

public class RegisterRequest
{
    [Required]
    [RegularExpression(@"\A[A-Za-z0-9_.-]{3,32}\z", ErrorMessage = "Логин должен содержать от 3 до 32 латинских букв, цифр или символов _ . -")]
    public string Login { get; set; } = string.Empty;

    [Required]
    [StringLength(128, MinimumLength = 12, ErrorMessage = "Пароль должен содержать от 12 до 128 символов")]
    public string Password { get; set; } = string.Empty;
}

public class LoginRequest
{
    [Required]
    [StringLength(32, MinimumLength = 3)]
    public string Login { get; set; } = string.Empty;

    [Required]
    [StringLength(128)]
    public string Password { get; set; } = string.Empty;
}

public record UserResponse(Guid Id, string Login);

public record LoginResponse(string AccessToken, DateTimeOffset ExpiresAt, UserResponse User);
