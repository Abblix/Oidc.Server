// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// The JWT Bearer assertion a grant is built from, recorded as used (RFC 7523 Section 3) only once the request
/// presenting it is answered with tokens, so a refusal its client can correct leaves the assertion for the corrected
/// request.
/// </summary>
/// <param name="Policy">Records the assertion and refuses one already used.</param>
/// <param name="Issuer">The issuer of the assertion, which scopes its identifier.</param>
/// <param name="JwtId">The assertion's jti.</param>
/// <param name="KeyId">The key the assertion was signed with, named when a replay is recorded.</param>
/// <param name="ExpiresAt">Until when the identifier is remembered.</param>
internal sealed record SingleUseAssertion(
	JwtBearerAssertionPolicy Policy,
	string Issuer,
	string JwtId,
	string? KeyId,
	DateTimeOffset ExpiresAt) : ISingleUseRedemption
{
	/// <inheritdoc />
	public Task<OidcError?> SpendAsync(TenantDefinition tenant, ClientInfo clientInfo)
		=> Policy.ReserveAsync(this, clientInfo);
}
