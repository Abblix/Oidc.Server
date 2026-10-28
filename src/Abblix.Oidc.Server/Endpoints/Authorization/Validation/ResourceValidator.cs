// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Settles the resources (RFC 8707) an authorization request is for: the ones it names, else the one its scopes refer
/// to where the tenant infers it. Each has to be registered at the tenant and one the client may get an access token
/// for. An access token returned at this endpoint, which no later token request settles, is also held here to the
/// tenant's default resource when nothing names one, and to one resource for a client held to one per token.
/// </summary>
/// <param name="resourceManager">The manager responsible for retrieving and validating resource information.</param>
public class ResourceValidator(IResourceManager resourceManager)
    : SyncAuthorizationContextValidatorBase
{
    /// <summary>
    /// Settles the resources of the request in the context, or refuses the request for them.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="context">The context containing the authorization request, which includes the resources to be
    /// validated.</param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> containing error details if validation fails,
    /// or null once the request's resources are settled.
    /// </returns>
    protected override AuthorizationRequestValidationError? Validate(TenantDefinition tenant, AuthorizationValidationContext context)
    {
        var request = context.Request;
        var requested = request.Resources;
        var scope = context.ClientInfo.ScopeServedFor(request.Scope) ?? [];

        if (requested is not { Length: > 0 })
        {
            if (!ResourceInference.TryInfer(tenant, scope, out var inferred, out var ambiguity))
                return context.Error(ErrorCodes.InvalidScope, ambiguity);

            if (inferred is null)
                return Refused(context, tenant, []);

            requested = [inferred];
        }

        if (!resourceManager.Validate(tenant, 
                requested,
                scope,
                out var resources,
                out var errorDescription))
        {
            return context.Error(ErrorCodes.InvalidTarget, errorDescription);
        }

        if (Refused(context, tenant, resources) is { } refusal)
            return refusal;

        context.Resources = resources;
        return null;
    }

    /// <summary>
    /// The refusal of the client's rules about <paramref name="resources"/>, or null. An access token returned at
    /// this endpoint has no token request to come where they could be settled.
    /// </summary>
    private static AuthorizationRequestValidationError? Refused(
        AuthorizationValidationContext context,
        TenantDefinition tenant,
        ResourceDefinition[] resources)
    {
        var finalForItsToken = context.Request.ResponseType.HasFlag(ResponseTypes.Token);
        return ResourceRefusals.Of(context.ClientInfo, tenant, resources, finalForItsToken) is { } refusal
            ? context.Error(ErrorCodes.InvalidTarget, refusal)
            : null;
    }
}
