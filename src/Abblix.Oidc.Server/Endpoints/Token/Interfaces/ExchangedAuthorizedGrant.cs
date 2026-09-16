// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// The grant an RFC 8693 token exchange builds from the presented subject_token: a session and an
/// authorization context of its own, plus the refresh token family the subject_token belonged to.
/// </summary>
/// <param name="AuthSession">The session synthesised for the exchanged token.</param>
/// <param name="Context">The authorization context the exchanged token is issued under.</param>
/// <param name="GrantId">The family the exchanged token joins, or <c>null</c> when the subject_token
/// belonged to none. The exchange hands out authority that came from the subject_token, so revoking that
/// token's family must refuse the exchanged token as well (RFC 9700 section 4.14.2).</param>
public record ExchangedAuthorizedGrant(
	AuthSession AuthSession,
	AuthorizationContext Context,
	string? GrantId)
	: AuthorizedGrant(AuthSession, Context);
