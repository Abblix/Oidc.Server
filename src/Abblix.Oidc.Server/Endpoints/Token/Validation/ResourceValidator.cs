// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ResourceIndicators;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Provides validation for resource-related data within token requests, ensuring that all requested resources are
/// recognized and appropriately scoped according to OAuth 2.0 and OpenID Connect standards.
/// </summary>
/// <param name="resourceManager">The manager responsible for validating and managing resource definitions.</param>
public class ResourceValidator(IResourceManager resourceManager): SyncTokenContextValidatorBase
{
    /// <summary>
    /// Validates the resources specified in a token request against known resource definitions.
    /// This validation ensures that only registered and approved resources are accessed by the client.
    /// </summary>
    /// <param name="context">The context of the token validation including the request and client information.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the validation fails, indicating the nature of the error and providing
    /// an error message; otherwise, null if the resource validation passes successfully.
    /// </returns>
    protected override OidcError? Validate(TokenValidationContext context)
    {
        var request = context.Request;

        // Proceed with validation only if there are resources specified in the request.
        if (request.Resources is { Length: > 0 })
        {
            // Validate the requested resources using the resource manager.
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

        // Return null indicating successful validation if there are no errors.
        return null;
    }
}
