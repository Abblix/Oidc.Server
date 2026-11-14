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
using Abblix.Oidc.Server.Features.MultiTenancy;
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
    public async Task<AuthorizationError?> BuildResponseAsync(
        TenantDefinition tenant,
        ValidAuthorizationRequest request,
        AuthorizedGrant authorizedGrant,
        SuccessfullyAuthenticated result)
    {
        // A code_challenge and a nonce must be transaction-specific (RFC 9700 section 2.1.1), so each is reserved for
        // this client before the code is issued, and a value it already used refuses the code. Here, once per code,
        // so the same request processed again across a login or consent redirect is not refused.
        var context = authorizedGrant.Context;
        if (context.CodeChallenge is { } codeChallenge &&
            !await reuseDetector.TryReserveAsync(
                tenant, context.ClientId, AuthorizationRequest.Parameters.CodeChallenge, codeChallenge))
        {
            return Reused(request, "The PKCE code_challenge must be unique per authorization request");
        }

        if (context.Nonce is { Length: > 0 } nonce &&
            !await reuseDetector.TryReserveAsync(tenant, context.ClientId, AuthorizationRequest.Parameters.Nonce, nonce))
        {
            return Reused(request, "The nonce must be unique per authorization request");
        }

        result.Code = await authorizationCodeService.GenerateAuthorizationCodeAsync(
            tenant,
            authorizedGrant,
            request.ClientInfo.AuthorizationCodeExpiresIn);

        return null;
    }

    private static AuthorizationError Reused(ValidAuthorizationRequest request, string description)
        => new(request.Model, ErrorCodes.InvalidRequest, description, request.ResponseMode, request.Model.RedirectUri);
}
