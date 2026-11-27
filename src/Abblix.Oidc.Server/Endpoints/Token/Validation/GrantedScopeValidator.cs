// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Validates the scope a token request names for a grant authorized earlier, once the grant is known: a scope only a
/// resource declares is available when a resource the request speaks for declares it
/// (<see cref="TokenRequestResources.SpokenFor"/>), one it names or, naming none, one its grant holds, as a refresh
/// naming no resource does (RFC 6749 section 6, RFC 8707 section 2.2).
/// </summary>
/// <remarks>
/// A refusal here spends nothing a corrected request needs: an authorization code and a refresh token are spent only
/// after validation, and a device code or a backchannel request, spent while its grant is authorized, is redeemed by
/// a request whose scope is ignored (<see cref="TokenRequestScope"/>). Any other grant is judged before it is built
/// (<see cref="ScopeValidator"/>).
/// </remarks>
/// <param name="scopeManager">The manager responsible for maintaining and validating scope definitions.</param>
/// <param name="resourceManager">The manager the definitions of the resources a request speaks for are read from.
/// </param>
public class GrantedScopeValidator(IScopeManager scopeManager, IResourceManager resourceManager)
    : SyncTokenContextValidatorBase
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, TokenValidationContext context)
    {
        if (!GrantsAuthorizedEarlier.Include(context.Request.GrantType))
            return null;

        var spokenFor = TokenRequestResources.SpokenFor(
            context.AuthorizedGrant.Context.Resources,
            from definition in context.Resources select definition.Resource);

        // A resource the host no longer knows declares no scope
        ResourceDefinition[] resources = [.. DefinitionsOf(tenant, spokenFor ?? [])];

        return TokenRequestScope.Judge(scopeManager, tenant, context, resources);
    }

    private IEnumerable<ResourceDefinition> DefinitionsOf(TenantDefinition tenant, Uri[] resources)
    {
        foreach (var resource in resources)
        {
            if (resourceManager.TryGet(tenant, resource, out var definition))
                yield return definition;
        }
    }
}
