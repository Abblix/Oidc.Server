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

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Validates the scopes specified in token requests using a scope manager to ensure their validity and availability.
/// This validator checks whether each requested scope is recognized and authorized for use, ensuring that clients
/// only receive permissions appropriate to their needs and in compliance with server policies.
/// </summary>
/// <param name="scopeManager">The manager responsible for maintaining and validating scope definitions.</param>
public class ScopeValidator(IScopeManager scopeManager): SyncTokenContextValidatorBase
{
    /// <summary>
    /// Validates the scopes specified in the token request context. This method ensures that all requested scopes
    /// are recognized by the scope manager and are permissible for the requesting client.
    /// </summary>
    /// <param name="context">The context containing the token request information,
    /// including the scopes to be validated.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if any of the requested scopes are invalid or not permitted,
    /// including an error code and a message describing the issue;
    /// otherwise, returns null indicating that all requested scopes are valid.
    /// </returns>
    protected override OidcError? Validate(TokenValidationContext context)
    {
        if (!scopeManager.Validate(
                context.Request.Scope,
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
