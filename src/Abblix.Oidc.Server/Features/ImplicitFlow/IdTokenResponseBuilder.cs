// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Tokens;

namespace Abblix.Oidc.Server.Features.ImplicitFlow;

/// <summary>
/// Builds the <c>id_token</c> response-type component of an authorization endpoint success
/// response - the OIDC identity-token contributor of the Implicit / Hybrid Flow. Generates
/// an ID token via <see cref="IIdentityTokenService"/> and stores it on the running
/// <see cref="SuccessfullyAuthenticated"/> result. Registered ONLY when a host calls
/// <c>EnableImplicitFlow()</c>; absent by default per OAuth 2.1 (draft) deprecation guidance.
/// Declares <c>implicit</c> in <see cref="GrantTypesSupported"/> so opting in surfaces the
/// implicit grant in discovery and registration-time gating without extra DI wiring.
/// </summary>
/// <remarks>
/// This builder is order-dependent: it reads <see cref="SuccessfullyAuthenticated.Code"/>
/// and <see cref="SuccessfullyAuthenticated.AccessToken"/> populated by earlier builders to
/// compute the <c>c_hash</c> and <c>at_hash</c> claims when those response components are
/// present. The orchestrator iterates response-type parts in canonical order (<c>code</c> →
/// <c>token</c> → <c>id_token</c>) so this dependency holds without explicit sequencing on
/// the builder side.
/// </remarks>
public class IdTokenResponseBuilder(IIdentityTokenService identityTokenService)
    : IAuthorizationResponseBuilder
{
    /// <inheritdoc />
    public string ResponseType => ResponseTypes.IdToken;

    /// <inheritdoc />
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.Implicit; }
    }

    /// <inheritdoc />
    public async Task BuildResponseAsync(
        ValidAuthorizationRequest request,
        AuthorizedGrant authorizedGrant,
        SuccessfullyAuthenticated result)
    {
        var responseType = request.Model.ResponseType;
        var standalone = !responseType.HasFlag(ResponseTypes.Code) && !responseType.HasFlag(ResponseTypes.Token);

        result.IdToken = await identityTokenService.CreateIdentityTokenAsync(
            authorizedGrant.AuthSession,
            authorizedGrant.Context,
            request.ClientInfo,
            standalone,
            result.Code,
            result.AccessToken?.EncodedJwt);
    }
}
