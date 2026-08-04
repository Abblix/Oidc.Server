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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Features.NoneFlow;

/// <summary>
/// Builds the <c>none</c> response-type component of an authorization endpoint success response
/// (OAuth 2.0 Multiple Response Type Encoding Practices §4). The none response type authorizes the
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
