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
/// This class is responsible for validating grant types in the context of client registration.
/// It checks that the grant types, based on the specified response types,
/// are present in the client's registration request. If any grant types are missing,
/// it generates a validation error indicating which grant types are required.
/// This validation ensures that clients are registered with appropriate grant types for OAuth 2.0 flows.
/// </summary>
public class GrantTypeValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Validates grant types based on response types in the client registration request.
    /// </summary>
    /// <param name="context">The validation context containing client registration data.</param>
    /// <returns>
    /// A RequestError if grant types are missing, or null if the request is valid.
    /// </returns>
    protected override RequestError? Validate(ClientRegistrationValidationContext context)
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
