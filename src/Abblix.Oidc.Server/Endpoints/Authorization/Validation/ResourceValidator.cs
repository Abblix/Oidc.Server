// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates resources specified in authorization requests to ensure they conform to registered definitions and policies.
/// This validator checks whether the resources requested in the authorization process are recognized by the system
/// and permitted for the requesting client, extending the base functionality of resource validation by incorporating
/// integration with the authorization context.
/// </summary>
/// <param name="resourceManager">The manager responsible for retrieving and validating resource information.</param>
public class ResourceValidator(IResourceManager resourceManager)
    : SyncAuthorizationContextValidatorBase
{
    /// <summary>
    /// Performs the validation of resource identifiers specified in the authorization request against the allowed
    /// resource definitions managed by the <see cref="IResourceManager"/>. This method ensures that the resources
    /// requested are known to the system and align with security and access policies.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="context">The context containing the authorization request, which includes the resources to be
    /// validated.</param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> containing error details if validation fails,
    /// or null if the validation is successful, indicating that all requested resources are recognized and permissible.
    /// </returns>
    protected override AuthorizationRequestValidationError? Validate(TenantDefinition tenant, AuthorizationValidationContext context)
    {
        var request = context.Request;
        var requested = request.Resources;

        if (requested is not { Length: > 0 })
        {
            if (!ResourceInference.TryInfer(tenant, request.Scope, out var inferred, out var ambiguity))
                return context.Error(ErrorCodes.InvalidScope, ambiguity);

            if (inferred is null)
                return null;

            requested = [inferred];
        }

        if (!resourceManager.Validate(tenant, 
                requested,
                request.Scope,
                out var resources,
                out var errorDescription))
        {
            return context.Error(ErrorCodes.InvalidTarget, errorDescription);
        }

        context.Resources = resources;
        return null;
    }
}
