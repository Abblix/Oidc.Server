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
    /// A AuthError if the validation fails, or null if the request is valid.
    /// </returns>
    protected override AuthError? Validate(ClientRegistrationValidationContext context)
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
