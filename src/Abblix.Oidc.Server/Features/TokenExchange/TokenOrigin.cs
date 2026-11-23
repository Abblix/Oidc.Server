// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// Whether a client may present a token at the token exchange grant, judged by the client the token was issued to:
/// the confused-deputy guard applied to subject and actor tokens alike.
/// </summary>
internal static class TokenOrigin
{
	/// <summary>
	/// Null when <paramref name="presenter"/> may present a token issued to <paramref name="ownerId"/>, otherwise why
	/// it may not.
	/// </summary>
	/// <param name="ownerId">The client the token was issued to, null when that cannot be determined.</param>
	/// <param name="presenter">The client presenting the token.</param>
	public static OidcError? Check(string? ownerId, ClientInfo presenter)
	{
		// AllowCrossClientSubjectTokenExchange is the single opt-out: a client trusted to present tokens it was not
		// issued is equally trusted to present one whose issuer cannot be read
		if (presenter.AllowCrossClientSubjectTokenExchange)
			return null;

		// An absent origin is the case the guard cannot decide: a token whose issuing client is undeterminable may or
		// may not belong to the presenting client, and skipping on absence would let a token shaped to hide its
		// origin pass the guard that a token naming another client fails
		if (ownerId is not { Length: > 0 })
		{
			return new OidcError(
				ErrorCodes.InvalidRequest,
				"The client the token was issued to could not be determined.");
		}

		if (!string.Equals(ownerId, presenter.ClientId, StringComparison.Ordinal))
		{
			return new OidcError(
				ErrorCodes.InvalidRequest,
				"The token was issued to a different client than the one presenting it.");
		}

		return null;
	}
}
