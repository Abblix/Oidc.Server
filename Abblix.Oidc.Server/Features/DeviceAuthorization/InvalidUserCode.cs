namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Indicates that the user code was not found or has expired.
/// </summary>
public record InvalidUserCode : UserCodeVerificationResult;