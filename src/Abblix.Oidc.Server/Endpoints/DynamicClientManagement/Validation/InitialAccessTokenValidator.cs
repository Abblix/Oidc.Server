// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

        // The audience is required and checked. An initial access token authorizes registration at this
        // server, so this server is its audience, and the shared validator accepts exactly that. The check
        // used to be off because the token carried no 'aud' at all - a token with no stated recipient, and
        // the one exception to the rule every other token here follows.
        var result = await jwtValidator.ValidateAsync(header.Parameter);

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
