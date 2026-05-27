using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Indicates that the user code was successfully verified and the request is pending authorization.
/// </summary>
/// <param name="ClientId">The client identifier that initiated the device authorization request.</param>
/// <param name="Scope">The requested scopes for the authorization.</param>
/// <param name="Resources">The requested resources (RFC 8707) for the authorization.</param>
/// <param name="AuthorizationDetails">RFC 9396 §3 Rich Authorization Requests array from
/// the original /device_authorization request. The host's user-verification UI renders these
/// for consent and threads the user's decision onto the AuthorizedGrant's AuthorizationContext.</param>
public record ValidUserCode(
    string ClientId,
    string[] Scope,
    Uri[]? Resources,
    JsonArray? AuthorizationDetails) : UserCodeVerificationResult;
