namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents an unauthorized response for a backchannel authentication request.
/// This response typically indicates that the request failed due to invalid client credentials
/// or other authorization-related issues.
/// </summary>
/// <param name="Error">The error code that identifies the type of failure.</param>
/// <param name="ErrorDescription">
/// A human-readable description of the error, providing more details about the failure.</param>
public record BackChannelAuthenticationUnauthorized(string Error, string ErrorDescription)
    : BackChannelAuthenticationError(Error, ErrorDescription);