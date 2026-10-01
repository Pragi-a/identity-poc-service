using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

const string issuer = "http://localhost:5101";
const string audience = "protected-service";
const string keyId = "identity-demo-rsa-key-1";

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options => options.AddDefaultPolicy(policy => policy
    .WithOrigins("http://localhost:4200", "http://localhost:4201")
    .AllowAnyHeader()
    .AllowAnyMethod()));

var rsa = RSA.Create(2048);
var signingKey = new RsaSecurityKey(rsa) { KeyId = keyId };
var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

var app = builder.Build();
app.UseCors();
app.MapGet("/", () => Results.Ok(new { service = "identity-service", issuer }));
app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

app.MapPost("/api/auth/login", (LoginRequest request) =>
{
    if (request.Username != "John Doe" || request.Password != "123456") return Results.Unauthorized();

    var allowedPermissions = new[] { "read", "add", "update", "delete" };
    var permissions = request.Permissions?.Where(allowedPermissions.Contains).Distinct().ToArray() ?? allowedPermissions;
    var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, "john.doe"),
        new Claim(JwtRegisteredClaimNames.UniqueName, "John Doe"),
        new Claim(ClaimTypes.Name, "John Doe"),
        new Claim(ClaimTypes.Role, "security-demo"),
        new Claim("scope", "protected.read")
    };
    claims.AddRange(permissions.Select(permission => new Claim("permission", permission)));
    var token = new JwtSecurityToken(issuer, audience, claims, DateTime.UtcNow,
        DateTime.UtcNow.AddMinutes(15), signingCredentials);

    return Results.Ok(new
    {
        access_token = new JwtSecurityTokenHandler().WriteToken(token),
        token_type = "Bearer",
        expires_in = 900,
        user = new { name = "John Doe", role = "security-demo", scope = "protected.read", permissions }
    });
});

app.MapGet("/.well-known/openid-configuration", () => Results.Ok(new
{
    issuer,
    jwks_uri = $"{issuer}/.well-known/jwks.json",
    token_endpoint = $"{issuer}/api/auth/login",
    id_token_signing_alg_values_supported = new[] { "RS256" }
}));

app.MapGet("/.well-known/jwks.json", () =>
{
    var publicKey = rsa.ExportParameters(false);
    return Results.Ok(new
    {
        keys = new[] { new
    {
        kty = "RSA", use = "sig", kid = keyId, alg = "RS256",
        n = Base64UrlEncoder.Encode(publicKey.Modulus), e = Base64UrlEncoder.Encode(publicKey.Exponent)
    } }
    });
});

app.Run();
record LoginRequest(string Username, string Password, string[]? Permissions);
