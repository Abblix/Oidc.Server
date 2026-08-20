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
