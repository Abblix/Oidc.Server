// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
        if (scope is null)
            return null;

        // A scope naming no value would be stored as no list at all, which the server reads as no restriction: the
        // opposite of what the client sent. A client registering without a restriction leaves the member out.
        if (scope.Length == 0)
            return ErrorFactory.InvalidClientMetadata("The scope names no value");

        return (from value in scope
            where !scopeManager.TryGet(value, out _)
            select ErrorFactory.InvalidClientMetadata($"Unknown scope: {value}")).FirstOrDefault();
    }
}
