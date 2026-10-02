// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Contains validated JWT data passed through the JWT Bearer validation pipeline.
/// </summary>
/// <param name="Jwt">The validated assertion.</param>
/// <param name="Subject">The assertion's subject.</param>
/// <param name="Issuer">The assertion's issuer.</param>
/// <param name="TrustedIssuer">The configuration of the issuer, when it is a configured trusted one.</param>
internal sealed record JwtBearerValidationContext(
	JsonWebToken Jwt,
	string Subject,
	string Issuer,
	TrustedIssuer? TrustedIssuer)
{
	/// <summary>
	/// The assertion's expiry as the expiration check read it, carried so that the replay reservation
	/// keys off a value already read rather than reading the accessor a second time.
	/// </summary>
	public DateTimeOffset? ExpiresAt { get; init; }
}
