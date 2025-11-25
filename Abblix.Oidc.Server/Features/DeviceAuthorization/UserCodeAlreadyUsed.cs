namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Indicates that the user code has already been used (approved or denied).
/// </summary>
public record UserCodeAlreadyUsed : UserCodeVerificationResult;