namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Indicates that the user code was successfully verified and the request is pending authorization.
/// </summary>
/// <param name="ClientId">The client identifier that initiated the device authorization request.</param>
/// <param name="Scope">The requested scopes for the authorization.</param>
/// <param name="Resources">The requested resources (RFC 8707) for the authorization.</param>
public record ValidUserCode(
    string ClientId,
    string[] Scope,
    Uri[]? Resources) : UserCodeVerificationResult;