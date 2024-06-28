using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Defines the details of user consents required for specific scopes and resources.
/// This record is used to manage and validate user consent for accessing specific scopes and resources,
/// ensuring that consent is explicitly granted according to the requirements of the application and compliance
/// standards.
/// </summary>
/// <param name="Scopes">An array of <see cref="ScopeDefinition"/> that represents the scopes for which user consent
/// is needed.</param>
/// <param name="Resources">An array of <see cref="ResourceDefinition"/> that represents the resources for which
/// user consent is needed.</param>
public record ConsentDefinition(ScopeDefinition[] Scopes, ResourceDefinition[] Resources);
