// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

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
    /// A ClientRegistrationValidationError if grant types are missing, or null if the request is valid.
    /// </returns>
    protected override ClientRegistrationValidationError? Validate(ClientRegistrationValidationContext context)
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
