// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Records the JWT Bearer assertion a grant is built from as used (RFC 7523 Section 3) before the processor it
/// wraps runs, and refuses the request when it already is.
/// </summary>
/// <remarks>
/// The record is made around the processor, after every validator of the token endpoint, as the authorization code
/// is spent by <see cref="AuthorizationCodeReusePreventingDecorator"/>: a request refused for something its client
/// can correct, such as a scope the assertion's issuer does not allow or a resource the client may not have, leaves
/// the assertion for the corrected request. A refusal of the processor it wraps comes after the record.
/// </remarks>
/// <param name="processor">The processor issuing the token once the assertion is recorded.</param>
/// <param name="assertionPolicy">Records the assertion and refuses one already used.</param>
internal sealed class JwtBearerAssertionReplayPreventingDecorator(
	ITokenRequestProcessor processor,
	JwtBearerAssertionPolicy assertionPolicy) : ITokenRequestProcessor
{
	/// <inheritdoc />
	public async Task<Result<TokenIssued, OidcError>> ProcessAsync(TenantDefinition tenant, ValidTokenRequest request)
	{
		if (request.AuthorizedGrant.SingleUseAssertion is { } assertion &&
			await assertionPolicy.ReserveAsync(assertion, request.ClientInfo) is { } replayed)
		{
			return replayed;
		}

		return await processor.ProcessAsync(tenant, request);
	}
}
