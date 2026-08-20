// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Enforces the consistency rule from OIDC DCR 1.0 §2 between <c>response_types</c> and
/// <c>grant_types</c>: a client requesting <c>code</c> must register the
/// <c>authorization_code</c> grant, and one requesting <c>token</c> or <c>id_token</c>
/// must register the <c>implicit</c> grant.
/// </summary>
public class GrantTypeValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error listing the grant types the client must
    /// register to support its declared response types, or <c>null</c> when the sets agree.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        var requiredGrantTypes = new HashSet<string>();

        foreach (var responseType in request.ResponseTypes)
        {
            if (responseType.HasFlag(ResponseTypes.Code))
                requiredGrantTypes.Add(GrantTypes.AuthorizationCode);

            if (responseType.HasFlag(ResponseTypes.Token) || responseType.HasFlag(ResponseTypes.IdToken))
                requiredGrantTypes.Add(GrantTypes.Implicit);
        }

        var missingGrantTypes = requiredGrantTypes.Except(request.GrantTypes).ToArray();
        if (missingGrantTypes.Length > 0)
        {
            return ErrorFactory.InvalidClientMetadata(
                $"The following grant types are required: {string.Join(", ", missingGrantTypes)}");
        }

        return null;
    }
}
