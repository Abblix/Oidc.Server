// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
                context.ClientInfo.AllowedScopes,
                out var scopeDefinitions,
                out var errorDescription))
        {
            return new OidcError(ErrorCodes.InvalidScope, errorDescription);
        }

        context.Scope = scopeDefinitions;
        return null;
    }
}
