// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// What an ID token is issued from (OpenID Connect Core 1.0 section 2): the end user's session, what was authorized,
/// the client it is issued to, and the values it binds itself to.
/// </summary>
/// <param name="AuthSession">The authentication session, which includes details such as the user's unique identifier
/// and the session's authentication time.</param>
/// <param name="AuthContext">The authorization context, providing the requested scopes and the claims to be included
/// in the identity token.</param>
/// <param name="ClientInfo">The client the identity token is issued to.</param>
/// <param name="IncludeUserClaims">Whether claims about the user are included in the identity token, as they are when
/// no access token is issued to fetch them from the UserInfo endpoint (OpenID Connect Core 1.0 section 5.4).</param>
/// <param name="AuthorizationCode">The authorization code issued alongside, which adds the <c>c_hash</c> claim, or
/// <see langword="null"/>.</param>
/// <param name="AccessToken">The access token issued alongside, which adds the <c>at_hash</c> claim, or
/// <see langword="null"/>.</param>
/// <param name="State">The <c>state</c> the authorization response echoes, or <see langword="null"/> when the token is
/// not returned there or the request carried none. Non-null adds the <c>s_hash</c> claim (Financial-grade API 1.0 Part
/// 2, section 5.1.1), which binds that state to the token.</param>
/// <param name="PushBindings">The CIBA push notification this token travels in, or <see langword="null"/> when it does
/// not. Non-null adds the two bindings CIBA Core 1.0 section 10.3.1 requires there and nowhere else - the request
/// identifier verbatim, and the refresh token's hash when one is sent.</param>
public sealed record IdentityTokenRequest(
    AuthSession AuthSession,
    AuthorizationContext AuthContext,
    ClientInfo ClientInfo,
    bool IncludeUserClaims,
    [property: Credential] string? AuthorizationCode,
    [property: Credential] string? AccessToken,
    string? State,
    PushDeliveryBindings? PushBindings = null);
