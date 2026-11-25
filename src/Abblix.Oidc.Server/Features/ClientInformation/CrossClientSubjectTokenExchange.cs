// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Which subject tokens issued to another client a client may present at the token exchange grant (RFC 8693).
/// </summary>
/// <remarks>
/// Exchanging a token issued to somebody else is the confused-deputy shape: the presenting client turns authority the
/// end user gave another client into a token of its own. An actor token is held to its own client whatever this says,
/// except under <see cref="Any"/>.
/// </remarks>
public enum CrossClientSubjectTokenExchange
{
	/// <summary>
	/// Only a subject token issued to the presenting client is exchanged; one issued to another client, or one whose
	/// client cannot be determined, is refused.
	/// </summary>
	Refused,

	/// <summary>
	/// A subject token issued to another client is exchanged when its audience names one of the presenting client's
	/// <see cref="ClientInfo.ResourceLocations"/>: the token was issued for the presenting client acting as a resource
	/// server, which delegates the call upstream, as a server behind an MCP client does.
	/// </summary>
	/// <remarks>
	/// The match is textual and exact, as <see cref="ClientInfo.ResourceLocations"/> describes. A refresh token is
	/// addressed to this server alone and is never exchanged by another client under this setting.
	/// </remarks>
	AddressedToClient,

	/// <summary>
	/// Any subject or actor token is exchanged whichever client it was issued to, one whose client cannot be
	/// determined included: the presenting client is a broker trusted with tokens issued to others.
	/// </summary>
	Any,
}
