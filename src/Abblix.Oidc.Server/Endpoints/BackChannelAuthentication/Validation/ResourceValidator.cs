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

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates resources specified in authorization requests to ensure they conform to registered definitions and policies.
/// This validator checks whether the resources requested in the authorization process are recognized by the system
/// and permitted for the requesting client, extending the base functionality of resource validation by incorporating
/// integration with the authorization context.
/// </summary>
/// <param name="resourceManager">The manager responsible for retrieving and validating resource information.</param>
public class ResourceValidator(IResourceManager resourceManager) : IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Performs the validation of resource identifiers specified in the authorization request against the allowed
    /// resource definitions managed by the <see cref="IResourceManager"/>. This method ensures that the resources
    /// requested are known to the system and align with security and access policies.
    /// </summary>
    /// <param name="context">The context containing the authorization request, which includes the resources to be
    /// validated.</param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> containing error details if validation fails,
    /// or null if the validation is successful, indicating that all requested resources are recognized and permissible.
    /// </returns>
    public Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    private OidcError? Validate(BackChannelAuthenticationValidationContext context)
    {
        var request = context.Request;

        if (request.Resources is { Length: > 0 })
        {
            if (!resourceManager.Validate(
                    request.Resources,
                    request.Scope,
                    out var resources,
                    out var errorDescription))
            {
                return new OidcError(ErrorCodes.InvalidTarget, errorDescription);
            }

            context.Resources = resources;
        }

        return null;
    }
}
