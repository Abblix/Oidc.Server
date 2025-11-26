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
using Abblix.Oidc.Server.Features.ScopeManagement;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Validates the scopes requested in a device authorization request.
/// </summary>
/// <param name="scopeManager">The service for managing and validating scopes.</param>
public class ScopeValidator(IScopeManager scopeManager) : IDeviceAuthorizationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(DeviceAuthorizationValidationContext context)
        => Task.FromResult(Validate(context));

    private OidcError? Validate(DeviceAuthorizationValidationContext context)
    {
        var scopes = context.Request.Scope ?? [];

        if (scopes.Contains(Scopes.OfflineAccess) &&
            context.ClientInfo.OfflineAccessAllowed != true)
        {
            return new OidcError(
                ErrorCodes.InvalidScope,
                "This client is not allowed to request for offline access");
        }

        if (!scopeManager.Validate(
                scopes,
                context.Resources,
                out var scopeDefinitions,
                out var errorDescription))
        {
            return new OidcError(ErrorCodes.InvalidScope, errorDescription);
        }

        context.Scope = scopeDefinitions;
        return null;
    }
}
