// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ResourceIndicators;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Provides validation for resource-related data within token requests, ensuring that all requested resources are
/// recognized and appropriately scoped according to OAuth 2.0 and OpenID Connect standards.
/// </summary>
public class ResourceValidator: SyncTokenContextValidatorBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ResourceValidator"/> class with a specific resource manager.
    /// </summary>
    /// <param name="resourceManager">The manager responsible for validating and managing resource definitions.</param>
    public ResourceValidator(IResourceManager resourceManager)
    {
        _resourceManager = resourceManager;
    }

    private readonly IResourceManager _resourceManager;

    /// <summary>
    /// Validates the resources specified in a token request against known resource definitions.
    /// This validation ensures that only registered and approved resources are accessed by the client.
    /// </summary>
    /// <param name="context">The context of the token validation including the request and client information.</param>
    /// <returns>
    /// A <see cref="TokenRequestError"/> if the validation fails, indicating the nature of the error and providing
    /// an error message; otherwise, null if the resource validation passes successfully.
    /// </returns>
    protected override TokenRequestError? Validate(TokenValidationContext context)
    {
        var request = context.Request;

        // Proceed with validation only if there are resources specified in the request.
        if (request.Resources is { Length: > 0 })
        {
            // Validate the requested resources using the resource manager.
            if (!_resourceManager.Validate(
                    request.Resources,
                    request.Scope,
                    out var resources,
                    out var errorDescription))
            {
                return new TokenRequestError(ErrorCodes.InvalidTarget, errorDescription);
            }

            context.Resources = resources;
        }

        // Return null indicating successful validation if there are no errors.
        return null;
    }
}
