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
