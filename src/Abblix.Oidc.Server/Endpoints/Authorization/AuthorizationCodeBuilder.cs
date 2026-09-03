// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Builds the <c>code</c> response-type component of an authorization endpoint success
/// response - the Authorization Code Flow contributor. Generates an authorization code via
/// <see cref="IAuthorizationCodeService"/> and stores it on the running
/// <see cref="SuccessfullyAuthenticated"/> result. Registered by default through
/// <c>AddAuthorizationEndpoint()</c>; covers the OAuth 2.1 (draft) recommended flow. Declares
/// <c>authorization_code</c> in <see cref="GrantTypesSupported"/> so the discovery
/// endpoint and registration-time gates aggregate it transparently.
/// </summary>
public class AuthorizationCodeBuilder(
    IAuthorizationCodeService authorizationCodeService,
    IAuthorizationValueReuseDetector reuseDetector)
    : IAuthorizationResponseBuilder
{
    /// <inheritdoc />
    public string ResponseType => ResponseTypes.Code;

    /// <inheritdoc />
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.AuthorizationCode; }
    }

    /// <inheritdoc />
    public async Task BuildResponseAsync(
        ValidAuthorizationRequest request,
        AuthorizedGrant authorizedGrant,
        SuccessfullyAuthenticated result)
    {
        result.Code = await authorizationCodeService.GenerateAuthorizationCodeAsync(
            authorizedGrant,
            request.ClientInfo.AuthorizationCodeExpiresIn);

        // Record this transaction's replay-protection values so a later reuse of a constant code_challenge
        // or nonce by the same client is detected (RFC 9700 section 2.1.1). Doing it here - once per issued code -
        // means the same request re-processed across a login or consent redirect is not flagged.
        var context = authorizedGrant.Context;
        if (context.CodeChallenge is { } codeChallenge)
            await reuseDetector.RecordAsync(context.ClientId, AuthorizationRequest.Parameters.CodeChallenge, codeChallenge);
        if (context.Nonce is { } nonce)
            await reuseDetector.RecordAsync(context.ClientId, AuthorizationRequest.Parameters.Nonce, nonce);
    }
}
