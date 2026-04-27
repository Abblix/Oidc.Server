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
/// Default implementation of <see cref="IRegistrationAccessTokenValidator"/>. Requires a
/// <c>Bearer</c> scheme, validates the JWT signature and lifetime via
/// <see cref="IAuthServiceJwtValidator"/>, then enforces that the token's <c>typ</c> is
/// <c>registration_access_token</c> and that its <c>sub</c> and <c>aud</c> both equal the
/// requested <c>client_id</c>.
/// </summary>
/// <param name="jwtValidator">JWT validator used for signature and lifetime checks.</param>
public class RegistrationAccessTokenValidator(IAuthServiceJwtValidator jwtValidator)
    : IRegistrationAccessTokenValidator
{
    /// <inheritdoc />
    public async Task<string?> ValidateAsync(AuthenticationHeaderValue? header, string clientId)
    {
        if (header?.Parameter == null)
            return $"The access token must be specified via '{HttpRequestHeaders.Authorization}' header";

        if (header.Scheme != TokenTypes.Bearer)
            return $"The scheme name '{header.Scheme}' is not supported";

        var result = await jwtValidator.ValidateAsync(
            header.Parameter,
            ValidationOptions.Default & ~ValidationOptions.ValidateAudience);

        if (result.TryGetFailure(out var error))
            return error.ErrorDescription;

        var token = result.GetSuccess();

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
