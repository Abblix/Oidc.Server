namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Represents a trusted external identity provider for JWT Bearer grant type.
/// </summary>
public record TrustedIssuer
{
    /// <summary>
    /// The issuer identifier (iss claim value) of the trusted identity provider.
    /// Must exactly match the 'iss' claim in JWT assertions from this provider.
    /// </summary>
    /// <example>https://accounts.google.com</example>
    /// <example>https://login.microsoftonline.com/{tenant-id}/v2.0</example>
    public required string Issuer { get; init; }

    /// <summary>
    /// The URL to the JSON Web Key Set (JWKS) endpoint for this issuer.
    /// Used to retrieve public keys for verifying JWT assertion signatures.
    /// </summary>
    /// <remarks>
    /// Typically this is the issuer's .well-known/jwks.json endpoint.
    /// The keys will be cached and refreshed according to standard JWKS caching policies.
    /// </remarks>
    /// <example>https://accounts.google.com/.well-known/jwks.json</example>
    /// <example>https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys</example>
    public required Uri JwksUri { get; init; }

    /// <summary>
    /// Optional description of this trusted issuer for documentation and logging purposes.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// The list of allowed signing algorithms for JWT assertions from this issuer.
    /// If specified, JWTs signed with algorithms not in this list will be rejected.
    /// If null or empty, the default secure algorithms are used: RS256, RS384, RS512, ES256, ES384, ES512.
    /// </summary>
    /// <remarks>
    /// This provides defense against algorithm substitution attacks (e.g., CVE-2015-9235).
    /// The 'none' algorithm is never allowed regardless of this setting.
    /// </remarks>
    public string[]? AllowedAlgorithms { get; init; }

    /// <summary>
    /// The list of allowed scopes that can be requested when using JWT assertions from this issuer.
    /// If null, all scopes are allowed. If specified, only listed scopes will be granted.
    /// </summary>
    public string[]? AllowedScopes { get; init; }
}
