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
using Abblix.Oidc.Server.Features.ReusePrevention;
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
public class NonceValidator(IAuthorizationValueReuseDetector reuseDetector) : IAuthorizationContextValidator
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
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
    {
        var request = context.Request;
        var responseType = request.ResponseType.NotNull(nameof(request.ResponseType));

        // The nonce is REQUIRED exactly when the response_type delivers an id_token from the
        // authorization endpoint, i.e. when it contains id_token (OIDC Core 1.0 §3.2.2.1 for
        // implicit, §3.3.2.11 for hybrid, as clarified by the Core errata "Nonce Implementation
        // Notes" and OIDC issues 972 and 1052): the nonce binds the front-channel id_token to the
        // client session. The "code token" combination is nominally a hybrid flow, yet it returns
        // NO id_token from the authorization endpoint, so the nonce stays OPTIONAL for it exactly
        // as in pure code flow (§3.1.2.1). Do not re-add a blanket "every hybrid combination
        // requires nonce" clause: that reading slipped in once and breaks OIDF certification,
        // whose module oidcc-ensure-request-without-nonce-succeeds-for-code-flow sends
        // response_type=code token without a nonce and requires the authorization to succeed.
        if (responseType.Contains(ResponseTypes.IdToken) && string.IsNullOrEmpty(request.Nonce))
        {
            return context.InvalidRequest(
                $"Nonce is required for the requested {Parameters.ResponseType}, as specified in OpenID Connect Core 1.0.");
        }

        // A nonce must be transaction-specific (RFC 9700 §2.1.1). When reuse detection is on, reject a
        // value this client already used for a previously issued authorization code.
        if (request.Nonce is { } nonce && !string.IsNullOrEmpty(nonce) &&
            await reuseDetector.IsReusedAsync(context.ClientInfo.ClientId, Parameters.Nonce, nonce))
        {
            return context.InvalidRequest("The nonce must be unique per authorization request");
        }

        return null;
    }
}
