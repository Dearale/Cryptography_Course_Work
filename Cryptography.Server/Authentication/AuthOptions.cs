using System.ComponentModel.DataAnnotations;

namespace Cryptography.Server.Authentication;

public class AuthOptions
{
    [Range(1, 168)]
    public int SessionHours { get; set; } = 12;

    [Range(100_000, 2_000_000)]
    public int PasswordIterations { get; set; } = 220_000;

    [Range(1, 10_000)]
    public int PermitLimit { get; set; } = 10;
}
