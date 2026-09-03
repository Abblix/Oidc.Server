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

namespace Abblix.Oidc.Server.Features.NoneFlow;

/// <summary>
/// Builds the <c>none</c> response-type component of an authorization endpoint success response
/// (OAuth 2.0 Multiple Response Type Encoding Practices section 4). The none response type authorizes the
/// request without returning any credentials, so this builder contributes nothing to the running
/// <see cref="SuccessfullyAuthenticated"/> result - the authorization endpoint returns only
/// <c>state</c> and, when advertised, <c>iss</c> (RFC 9207). Registered by opt-in through
/// <c>EnableNoneFlow()</c>. Unlike the other response types it declares no grant type, because
/// it issues no code or token to be exchanged later.
/// </summary>
public class NoneResponseBuilder : IAuthorizationResponseBuilder
{
    /// <inheritdoc />
    public string ResponseType => ResponseTypes.None;

    /// <inheritdoc />
    public IEnumerable<string> GrantTypesSupported => [];

    /// <inheritdoc />
    public Task BuildResponseAsync(
        ValidAuthorizationRequest request,
        AuthorizedGrant authorizedGrant,
        SuccessfullyAuthenticated result)
        => Task.CompletedTask;
}
