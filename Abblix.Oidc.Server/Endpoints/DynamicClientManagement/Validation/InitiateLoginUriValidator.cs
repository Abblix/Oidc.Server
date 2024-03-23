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

using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// This class is responsible for validating the Initiate Login URI specified in the client registration request.
/// It ensures that the URI is an absolute HTTPS URI.
/// </summary>
public class InitiateLoginUriValidator: SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Validates the Initiate Login URI specified in the client registration request.
    /// </summary>
    /// <param name="context">The validation context containing client registration data.</param>
    /// <returns>
    /// A ClientRegistrationValidationError if the validation fails, or null if the request is valid.
    /// </returns>
    protected override ClientRegistrationValidationError? Validate(ClientRegistrationValidationContext context)
    {
        var model = context.Request;
        if (model.InitiateLoginUri != null)
        {
            if (!model.InitiateLoginUri.IsAbsoluteUri)
            {
                return ErrorFactory.InvalidClientMetadata($"The {Parameters.InitiateLoginUri} is not an absolute URI");
            }

            if (model.InitiateLoginUri.Scheme != Uri.UriSchemeHttps)
            {
                return ErrorFactory.InvalidClientMetadata($"The {Parameters.InitiateLoginUri} must have HTTPS scheme");
            }
        }

        return null;
    }
}
