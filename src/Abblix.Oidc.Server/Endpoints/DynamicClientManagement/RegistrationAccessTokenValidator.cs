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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default implementation of <see cref="IRegistrationAccessTokenValidator"/>. Requires a
/// <c>Bearer</c> scheme, validates the JWT signature and lifetime via
/// <see cref="IAuthServiceJwtValidator"/> (which requires the audience to name this server, the party that
/// reads the token), then enforces that the token's <c>typ</c> is <c>registration_access_token</c> and that
/// its <c>sub</c> equals the requested <c>client_id</c> - the claim carrying the association RFC 7592
/// Section 1.2 describes.
/// </summary>
/// <param name="jwtValidator">JWT validator used for signature and lifetime checks.</param>
public class RegistrationAccessTokenValidator(IAuthServiceJwtValidator jwtValidator)
    : IRegistrationAccessTokenValidator
{
    /// <inheritdoc />
    public async Task<string?> ValidateAsync(AuthenticationHeaderValue? header, string clientId, string? expectedTokenId)
    {
        if (header?.Parameter == null)
            return $"The access token must be specified via '{HttpRequestHeaders.Authorization}' header";

        if (header.Scheme != TokenTypes.Bearer)
            return $"The scheme name '{header.Scheme}' is not supported";

        // The audience is required and checked: it names this server, which is what reads the token. Which
        // registration the token is about is a separate question, and the subject answers it - see below.
        var result = await jwtValidator.ValidateAsync(header.Parameter);

        if (result.TryGetFailure(out var error))
            return error.ErrorDescription;

        var token = result.GetSuccess();

        var tokenType = token.Header.Type;
        var subject = token.Payload.Subject;

        if (tokenType != JwtTypes.RegistrationAccessToken)
            return $"Invalid token type: {tokenType}";

        // RFC 7592 Section 1.2: the token "is associated with a particular registered client". The subject
        // carries that association, so a token cannot manage a registration other than the one it names.
        if (subject != clientId)
            return "The access token unauthorized";

        // RFC 7592 §5: bind the token to the client so a rotated token invalidates its
        // predecessors. Enforced only when the client records the current jti - a null expectation
        // keeps statically configured clients and pre-existing records working unchanged.
        if (expectedTokenId != null && token.Payload.JwtId != expectedTokenId)
            return "The access token unauthorized";

        return null;
    }
}
