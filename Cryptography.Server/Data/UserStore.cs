using Cryptography.Contracts;
using Microsoft.Data.Sqlite;

namespace Cryptography.Server.Data;

public class UserStore
{
    private string connectionString;

    public UserStore(IConfiguration configuration, IWebHostEnvironment environment)
    {
        string path = Path.GetFullPath(configuration["Database:Path"] ?? "App_Data/server.db", environment.ContentRootPath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            ForeignKeys = true,
            DefaultTimeout = 5
        }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS Users (
                Id TEXT PRIMARY KEY,
                Login TEXT NOT NULL,
                NormalizedLogin TEXT NOT NULL UNIQUE,
                PasswordHash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS Sessions (
                TokenHash TEXT PRIMARY KEY,
                UserId TEXT NOT NULL REFERENCES Users(Id) ON DELETE CASCADE,
                ExpiresAt INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_Sessions_ExpiresAt ON Sessions(ExpiresAt);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<bool> CreateUserAsync(User user, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Id, Login, NormalizedLogin, PasswordHash)
            VALUES ($id, $login, $normalizedLogin, $hash)
            ON CONFLICT (NormalizedLogin) DO NOTHING;
            """;
        command.Parameters.AddWithValue("$id", user.Id.ToString());
        command.Parameters.AddWithValue("$login", user.Login);
        command.Parameters.AddWithValue("$normalizedLogin", user.Login.ToUpperInvariant());
        command.Parameters.AddWithValue("$hash", user.PasswordHash);

        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<User?> FindUserAsync(string login, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT Id, Login, PasswordHash FROM Users WHERE NormalizedLogin = $login;";
        command.Parameters.AddWithValue("$login", login.ToUpperInvariant());

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
            return null;

        return new User { Id = Guid.Parse(reader.GetString(0)), Login = reader.GetString(1), PasswordHash = reader.GetString(2) };
    }

    public async Task UpdatePasswordHashAsync(Guid id, string hash, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET PasswordHash = $hash WHERE Id = $id;";
        command.Parameters.AddWithValue("$id", id.ToString());
        command.Parameters.AddWithValue("$hash", hash);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task CreateSessionAsync(string tokenHash, Guid userId, long expiresAt, long now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            DELETE FROM Sessions WHERE ExpiresAt <= $now;
            INSERT INTO Sessions (TokenHash, UserId, ExpiresAt) VALUES ($hash, $userId, $expiresAt);
            """;
        command.Parameters.AddWithValue("$hash", tokenHash);
        command.Parameters.AddWithValue("$userId", userId.ToString());
        command.Parameters.AddWithValue("$expiresAt", expiresAt);
        command.Parameters.AddWithValue("$now", now);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<UserResponse?> FindSessionUserAsync(string tokenHash, long now, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT Users.Id, Users.Login FROM Sessions
            JOIN Users ON Users.Id = Sessions.UserId
            WHERE Sessions.TokenHash = $hash AND Sessions.ExpiresAt > $now;
            """;
        command.Parameters.AddWithValue("$hash", tokenHash);
        command.Parameters.AddWithValue("$now", now);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);

        return await reader.ReadAsync(cancellationToken)
            ? new UserResponse(Guid.Parse(reader.GetString(0)), reader.GetString(1)) : null;
    }

    public async Task DeleteSessionAsync(string tokenHash, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "DELETE FROM Sessions WHERE TokenHash = $hash;";
        command.Parameters.AddWithValue("$hash", tokenHash);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
