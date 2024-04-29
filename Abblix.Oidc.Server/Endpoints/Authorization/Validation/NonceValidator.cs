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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Utils;
using static Abblix.Oidc.Server.Model.AuthorizationRequest;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Implements nonce validation for authorization requests in compliance with OAuth 2.0 and OpenID Connect specifications.
/// This validator ensures the presence of a nonce parameter when the response type includes an ID token, as by
/// OpenID Connect Core 1.0 specification. It extends <see cref="SyncAuthorizationContextValidatorBase"/> for
/// synchronous validation.
/// Refer to RFC 6749 and OpenID Connect Core 1.0 for more details on authorization request parameters.
/// </summary>
public class NonceValidator : SyncAuthorizationContextValidatorBase
{
    /// <summary>
    /// Validates the nonce in the authorization request as per OpenID Connect Core 1.0 specifications.
    /// </summary>
    /// <param name="context">The <see cref="AuthorizationValidationContext"/> containing the authorization request
    /// to be validated.</param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> if the validation fails due to a missing nonce
    /// when the response type includes an ID token, as by OpenID Connect Core 1.0;
    /// otherwise, null indicating successful validation.
    /// </returns>
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        var request = context.Request;
        var responseType = request.ResponseType;

        // Validate nonce as per OpenID Connect Core 1.0 requirements
        if (responseType.NotNull(nameof(responseType)).Contains(ResponseTypes.IdToken) &&
            string.IsNullOrEmpty(request.Nonce))
        {
            return context.InvalidRequest($"Nonce is when {Parameters.ResponseType} includes '{ResponseTypes.IdToken}', as specified in OpenID Connect Core 1.0.");
        }

        return null;
    }
}
