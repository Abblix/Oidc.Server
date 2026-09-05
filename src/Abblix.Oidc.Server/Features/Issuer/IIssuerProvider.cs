// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// Provides a mechanism to retrieve the issuer identifier for the OpenID Connect provider.
/// The issuer identifier is a fundamental part of the token validation process,
/// as it indicates the origin of the token.
/// </summary>
public interface IIssuerProvider
{
	/// <summary>
	/// Retrieves the issuer identifier that represents the OpenID Connect provider.
	/// This identifier is used in various OpenID Connect responses and tokens to
	/// ensure the identity of the issuing server.
	/// </summary>
	/// <returns>A string representing the issuer identifier.</returns>
	string GetIssuer();
}
