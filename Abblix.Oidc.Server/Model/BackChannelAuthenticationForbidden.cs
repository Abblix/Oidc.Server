namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a forbidden response for a backchannel authentication request.
/// This response typically indicates that the client is authenticated but does not have permission
/// to perform the requested operation.
/// </summary>
/// <param name="Error">The error code that identifies the type of failure.</param>
/// <param name="ErrorDescription">
/// A human-readable description of the error, providing more details about the failure.</param>
public record BackChannelAuthenticationForbidden(string Error, string ErrorDescription)
    : BackChannelAuthenticationError(Error, ErrorDescription);