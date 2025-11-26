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
using Abblix.Oidc.Server.Features.ResourceIndicators;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Validates the resources requested in a device authorization request.
/// </summary>
/// <param name="resourceManager">The service for managing and validating resources.</param>
public class ResourceValidator(IResourceManager resourceManager) : IDeviceAuthorizationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(DeviceAuthorizationValidationContext context)
        => Task.FromResult(Validate(context));

    private OidcError? Validate(DeviceAuthorizationValidationContext context)
    {
        var request = context.Request;

        if (request.Resources is { Length: > 0 })
        {
            if (!resourceManager.Validate(
                    request.Resources,
                    request.Scope ?? [],
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
