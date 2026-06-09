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
