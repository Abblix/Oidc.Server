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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.Options;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the initial access token on client registration requests per RFC 7591 Section 3
/// and RFC 6750 Bearer Token Usage. When <see cref="OidcOptions.RequireInitialAccessToken"/> is enabled,
/// checks JWT signature, expiration, type, and revocation status.
/// Skipped for update operations and when the feature is disabled.
/// </summary>
/// <param name="jwtValidator">Validates JWT signature and expiration.</param>
/// <param name="revocationProvider">Checks whether the token has been revoked.</param>
/// <param name="options">OIDC configuration options.</param>
public class InitialAccessTokenValidator(
    IAuthServiceJwtValidator jwtValidator,
    IInitialAccessTokenRevocationProvider revocationProvider,
    IOptionsMonitor<OidcOptions> options) : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        if (context.Operation != DynamicClientOperation.Register || !options.CurrentValue.RequireInitialAccessToken)
            return null;

        var header = context.Request.AuthorizationHeader;
        if (header?.Parameter == null)
        {
            return new OidcError(ErrorCodes.InvalidToken,
                $"The access token must be specified via '{HttpRequestHeaders.Authorization}' header");
        }

        if (header.Scheme != TokenTypes.Bearer)
        {
            return new OidcError(ErrorCodes.InvalidToken,
                $"The scheme name '{header.Scheme}' is not supported");
        }

        // Skip audience validation: initial access tokens authorize registration at the issuer itself,
        // so no audience claim is set or expected.
        var result = await jwtValidator.ValidateAsync(
            header.Parameter,
            ValidationOptions.Default & ~ValidationOptions.ValidateAudience);

        if (result.TryGetFailure(out var error))
            return new OidcError(ErrorCodes.InvalidToken, error.ErrorDescription);

        var token = result.GetSuccess();

        if (token.Header.Type != JwtTypes.InitialAccessToken)
        {
            return new OidcError(ErrorCodes.InvalidToken,
                $"Invalid token type: {token.Header.Type}");
        }

        var subject = token.Payload.Subject;
        if (string.IsNullOrEmpty(subject))
            return new OidcError(ErrorCodes.InvalidToken, "Token subject is missing");

        if (await revocationProvider.IsRevokedAsync(subject))
            return new OidcError(ErrorCodes.InvalidToken, "The access token has been revoked");

        return null;
    }
}
