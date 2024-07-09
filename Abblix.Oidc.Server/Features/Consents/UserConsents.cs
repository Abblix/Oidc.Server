using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Represents the state of user consents in an authorization flow, categorizing them into granted, denied, and pending.
/// </summary>
public record UserConsents
{
    /// <summary>
    /// The consents that have been explicitly granted by the user.
    /// These consents cover scopes and resources the user has agreed to provide access to.
    /// </summary>
    public ConsentDefinition Granted { get; set; } = new(
        Array.Empty<ScopeDefinition>(),
        Array.Empty<ResourceDefinition>());

    /// <summary>
    /// The consents that are still pending a decision by the user.
    /// These include scopes and resources that have been requested but not yet explicitly approved or denied.
    /// </summary>
    public ConsentDefinition Pending { get; set; } = new(
        Array.Empty<ScopeDefinition>(),
        Array.Empty<ResourceDefinition>());
};
