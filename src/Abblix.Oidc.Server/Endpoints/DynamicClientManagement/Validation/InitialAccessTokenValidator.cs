// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.Options;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the initial access token on client registration requests per RFC 7591 Section 3
/// and RFC 6750 Bearer Token Usage. When <see cref="OidcOptions.RequireInitialAccessToken"/> is enabled,
/// checks JWT signature, expiration, type, and revocation status, the last through the token status check of
/// <see cref="IAuthServiceJwtValidator"/>, which refuses a token whose identifier is recorded as revoked.
/// Skipped for update operations and when the feature is disabled.
/// </summary>
/// <param name="jwtValidator">Validates JWT signature and expiration.</param>
/// <param name="options">OIDC configuration options.</param>
public class InitialAccessTokenValidator(
    IAuthServiceJwtValidator jwtValidator,
    IOptionsMonitor<OidcOptions> options) : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        if (context.Operation != DynamicClientOperation.Register || !options.CurrentValue.RequireInitialAccessToken)
            return null;

        // RFC 7591 section 3.2.2 answers an error "appropriate to the OAuth 2.0 token type", and RFC 6750 section 3.1
        // names a request that "uses more than one method for including an access token" an invalid_request
        if (context.Request.HasMoreThanOneAuthorizationHeader)
            return Common.Validation.ErrorFactory.MoreThanOneBearerAuthorizationHeader;

        // RFC 6750 section 3.1: a request that "lacks any authentication information (e.g., the client was unaware that
        // authentication is necessary or attempted using an unsupported authentication method)" gets no error code, so
        // the typed marker has the challenge builder leave the error attributes out. A token in the query is not read
        // here at all, so the request carrying one lacks it alike
        var header = context.Request.AuthorizationHeader;
        if (header == null)
        {
            return new MissingAuthenticationError(
                $"The access token must be specified via '{HttpRequestHeaders.Authorization}' header");
        }

        if (!header.HasScheme(TokenTypes.Bearer))
            return new MissingAuthenticationError($"The scheme name '{header.Scheme}' is not supported");

        if (header.Parameter == null)
        {
            return new OidcError(ErrorCodes.InvalidToken,
                $"The access token must be specified via '{HttpRequestHeaders.Authorization}' header");
        }

        // The audience is required and checked. An initial access token authorizes registration at this
        // server, so this server is its audience, and the shared validator accepts exactly that. The check
        // used to be off because the token carried no 'aud' at all - a token with no stated recipient, and
        // the one exception to the rule every other token here follows.
        var result = await jwtValidator.ValidateAsync(
            tenant,
            client: null,
            header.Parameter,
            TokenTypePolicy.Exactly(JwtTypes.InitialAccessToken),
            // A token that never expires could not be revoked for good: its revocation is kept until it expires
            ValidationOptions.Default | ValidationOptions.RequireExpirationTime);

        if (result.TryGetFailure(out var error))
            return new OidcError(ErrorCodes.InvalidToken, error.ErrorDescription);

        var token = result.GetSuccess();

        var subject = token.Payload.Subject;
        if (string.IsNullOrEmpty(subject))
            return new OidcError(ErrorCodes.InvalidToken, "Token subject is missing");

        // The identifier the token is revoked by: a token without one could never be refused once issued
        if (string.IsNullOrEmpty(token.Payload.JwtId))
            return new OidcError(ErrorCodes.InvalidToken, "Token identifier is missing");

        return null;
    }
}
