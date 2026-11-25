// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Which client a token this server issued belongs to: the one question every check of who may act on a token, or
/// whose profile a token is processed under, asks.
/// </summary>
/// <remarks>
/// Each kind names its owner in a different place, so reading <c>client_id</c> alone takes a token naming none
/// there for one nobody owns, and lets every client act on it. An access or refresh token carries the client it
/// was issued to in <c>client_id</c>. A registration access token names, as its subject, the client whose
/// registration it manages (RFC 7592 section 3), and is that client's credential; its audience is this server. An
/// initial access token belongs to whoever was given it to register clients (RFC 7591 section 3), which is no
/// client of this server. Any other token, an ID token above all, belongs to the client its payload names:
/// <c>client_id</c>, else <c>azp</c>, else its sole audience.
/// </remarks>
internal static class TokenOwnership
{
	/// <summary>
	/// The identifier of the client <paramref name="token"/> belongs to, or null when it belongs to no client.
	/// </summary>
	/// <param name="token">A token this server issued, already found authentic.</param>
	public static string? OwnerOf(this JsonWebToken token)
	{
		var type = token.Header.Type;
		if (JwtTypeName.Matches(type, JsonWebTokenTypes.AccessToken) || JwtTypeName.Matches(type, JwtTypes.RefreshToken))
			return token.Payload.ClientId;

		if (JwtTypeName.Matches(type, JwtTypes.RegistrationAccessToken))
			return token.Payload.Subject;

		if (JwtTypeName.Matches(type, JwtTypes.InitialAccessToken))
			return null;

		return token.Payload.NamedClientId();
	}

	/// <summary>
	/// Whether <paramref name="token"/> belongs to the client <paramref name="clientId"/>; a token belonging to no
	/// client belongs to none of them.
	/// </summary>
	/// <param name="token">A token this server issued, already found authentic.</param>
	/// <param name="clientId">The client asking.</param>
	public static bool BelongsTo(this JsonWebToken token, string clientId)
		=> OwnerOf(token) is { } owner && string.Equals(owner, clientId, StringComparison.Ordinal);
}
