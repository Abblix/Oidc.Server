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
public class ResourceValidator: IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ResourceValidator"/> class, setting up the resource manager
    /// responsible for maintaining and validating the definitions of resources.
    /// </summary>
    /// <param name="resourceManager">The manager responsible for retrieving and validating resource information.
    /// </param>
    public ResourceValidator(IResourceManager resourceManager)
    {
        _resourceManager = resourceManager;
    }

    private readonly IResourceManager _resourceManager;

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
    public Task<RequestError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    private RequestError? Validate(BackChannelAuthenticationValidationContext context)
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
                return new RequestError(ErrorCodes.InvalidTarget, errorDescription);
            }

            context.Resources = resources;
        }

        // Return null indicating successful validation if there are no errors.
        return null;
    }
}
