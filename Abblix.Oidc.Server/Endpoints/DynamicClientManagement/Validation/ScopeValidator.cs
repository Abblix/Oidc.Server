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

using System.Linq;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ScopeManagement;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the scope values in a client registration request per RFC 7591 Section 2.
/// Each requested scope must be recognized by the server.
/// </summary>
/// <param name="scopeManager">Provides access to known scope definitions.</param>
public class ScopeValidator(IScopeManager scopeManager) : SyncClientRegistrationContextValidator
{
    /// <inheritdoc />
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var scope = context.Request.Scope;
        if (scope is not { Length: > 0 })
            return null;

        return (from value in scope
            where !scopeManager.TryGet(value, out _)
            select ErrorFactory.InvalidClientMetadata($"Unknown scope: {value}")).FirstOrDefault();
    }
}
