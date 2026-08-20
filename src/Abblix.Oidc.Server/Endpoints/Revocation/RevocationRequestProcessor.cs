// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Revocation;

/// <summary>
/// Processes revocation requests for tokens.
/// This class is responsible for handling the logic associated with revoking tokens, such as access tokens or refresh tokens.
/// </summary>
/// <param name="tokenRegistry">The token registry to be used by this processor for managing token statuses.</param>
/// <param name="clock">Provides the current time for timestamping the revocation operation.</param>
public class RevocationRequestProcessor(
	ITokenRegistry tokenRegistry,
	TimeProvider clock) : IRevocationRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a valid revocation request.
	/// This method handles the revocation of a specified token by changing its status to 'Revoked' in the token registry.
	/// The operation ensures that the token is no longer valid for any future requests.
	/// </summary>
	/// <param name="request">The revocation request to be processed. Contains information about the token to be revoked.</param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation, which upon completion will yield a <see cref="Result{TSuccess, TFailure}"/>
	/// containing either <see cref="TokenRevoked"/> on success or <see cref="OidcError"/> on failure.
	/// </returns>
	public async Task<Result<TokenRevoked, OidcError>> ProcessAsync(ValidRevocationRequest request)
	{
		var payload = request.Token?.Payload;
		if (payload is { JwtId: {} jwtId, ExpiresAt: {} expiresAt })
			await tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt);

		return new TokenRevoked(
			TokenId: payload?.JwtId,
			TokenTypeHint: request.Model.TokenTypeHint,
			RevokedAt: clock.GetUtcNow());
	}
}
