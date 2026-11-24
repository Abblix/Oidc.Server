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
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// Whether a client may present a token at the token exchange grant, judged by the client the token was issued to and,
/// for a subject token, by whom it is addressed to: the confused-deputy guard, as
/// <see cref="ClientInfo.CrossClientSubjectTokenExchange"/> sets it for the presenting client.
/// </summary>
internal static class TokenOrigin
{
	/// <summary>
	/// Null when <paramref name="presenter"/> may present a subject token issued to <paramref name="ownerId"/> and
	/// addressed to <paramref name="audiences"/>, otherwise why it may not.
	/// </summary>
	/// <param name="tenant">The tenant the exchange is served at.</param>
	/// <param name="ownerId">The client the token was issued to, null when that cannot be determined.</param>
	/// <param name="audiences">The token's audience, null when it states none.</param>
	/// <param name="presenter">The client presenting the token.</param>
	public static OidcError? CheckSubject(
		TenantDefinition tenant,
		string? ownerId,
		IEnumerable<string>? audiences,
		ClientInfo presenter)
	{
		switch (presenter.CrossClientSubjectTokenExchange)
		{
			case CrossClientSubjectTokenExchange.Any:
				return null;

			case CrossClientSubjectTokenExchange.Refused:
				return OwnerCheck(ownerId, presenter);

			case CrossClientSubjectTokenExchange.AddressedToClient:
				// A token addressed to one of the presenting client's own locations was issued for it as a resource
				// server, whichever client asked for it, so its origin need not be known; any other is held to its owner.
				// The issuer is the audience of every token whose request named no resource, so it is no location of a
				// client (CrossClientSubjectTokenExchangeCheck refuses one at startup) and admits nothing here
				return audiences is not null &&
				       audiences.Any(audience => !tenant.IssuerIsNamedBy(audience) && presenter.IsResourceServerFor(audience))
					? null
					: OwnerCheck(ownerId, presenter);

			default:
				throw new ArgumentOutOfRangeException(
					nameof(presenter),
					presenter.CrossClientSubjectTokenExchange,
					"A cross-client subject token exchange setting this server does not define.");
		}
	}

	/// <summary>
	/// Null when <paramref name="presenter"/> may present an actor token issued to <paramref name="ownerId"/>,
	/// otherwise why it may not.
	/// </summary>
	/// <remarks>
	/// The actor token identifies the party acting, so only a broker trusted with any token presents one issued to
	/// another client; a resource server delegating upstream acts as itself.
	/// </remarks>
	/// <param name="ownerId">The client the token was issued to, null when that cannot be determined.</param>
	/// <param name="presenter">The client presenting the token.</param>
	public static OidcError? CheckActor(string? ownerId, ClientInfo presenter)
	{
		switch (presenter.CrossClientSubjectTokenExchange)
		{
			case CrossClientSubjectTokenExchange.Any:
				return null;

			case CrossClientSubjectTokenExchange.Refused:
			case CrossClientSubjectTokenExchange.AddressedToClient:
				return OwnerCheck(ownerId, presenter);

			default:
				throw new ArgumentOutOfRangeException(
					nameof(presenter),
					presenter.CrossClientSubjectTokenExchange,
					"A cross-client subject token exchange setting this server does not define.");
		}
	}

	/// <summary>
	/// Null when the token was issued to <paramref name="presenter"/>, otherwise why it is refused.
	/// </summary>
	private static OidcError? OwnerCheck(string? ownerId, ClientInfo presenter)
	{
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
