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

using System.Net.Http.Headers;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the validation of registration access tokens, ensuring they adhere to JWT standards and
/// are authorized for use by specific clients.
/// </summary>
/// <param name="jwtValidator">An implementation of <see cref="IAuthServiceJwtValidator"/> responsible for the
/// JWT validation logic.</param>
public class RegistrationAccessTokenValidator(IAuthServiceJwtValidator jwtValidator) : IRegistrationAccessTokenValidator
{
    /// <summary>
    /// Asynchronously validates a registration access token, verifying its format, type, and authorization for
    /// the intended client.
    /// </summary>
    /// <param name="header">The HTTP Authorization header containing the bearer token to be validated.</param>
    /// <param name="clientId">The unique identifier of the client that the token is supposed to authorize.</param>
    /// <returns>
    /// A task that results in a nullable string; returns null if the token is valid and authorized for the specified
    /// client, or an error message detailing the reason for validation failure.
    /// </returns>
    /// <remarks>
    /// This method is crucial for securing client registration and management endpoints by ensuring that only valid
    /// and authorized registration access tokens can perform operations. It checks the token's type, audience
    /// and subject against the expected values, employing JWT validation to ascertain its integrity and applicability.
    /// </remarks>
    public async Task<string?> ValidateAsync(AuthenticationHeaderValue? header, string clientId)
    {
        if (header?.Parameter == null)
            return $"The access token must be specified via '{HttpRequestHeaders.Authorization}' header";

        if (header.Scheme != TokenTypes.Bearer)
            return $"The scheme name '{header.Scheme}' is not supported";

        var result = await jwtValidator.ValidateAsync(
            header.Parameter,
            ValidationOptions.Default & ~ValidationOptions.ValidateAudience);

        if (!result.TryGetSuccess(out var token))
        {
            var error = result.GetFailure();
            return error.ErrorDescription;
        }

        var tokenType = token.Header.Type;
        var audiences = token.Payload.Audiences;
        var subject = token.Payload.Subject;

        if (tokenType != JwtTypes.RegistrationAccessToken)
            return $"Invalid token type: {tokenType}";

        if (subject != clientId || !audiences.Contains(clientId))
            return "The access token unauthorized";

        return null;
    }
}
