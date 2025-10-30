// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
public class RevocationRequestProcessor(ITokenRegistry tokenRegistry) : IRevocationRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a valid revocation request.
	/// This method handles the revocation of a specified token by changing its status to 'Revoked' in the token registry.
	/// The operation ensures that the token is no longer valid for any future requests.
	/// </summary>
	/// <param name="request">The revocation request to be processed. Contains information about the token to be revoked.</param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation, which upon completion will yield a <see cref="Result{TSuccess, TFailure}"/>
	/// containing either <see cref="TokenRevoked"/> on success or <see cref="AuthError"/> on failure.
	/// </returns>
	public async Task<Result<TokenRevoked, AuthError>> ProcessAsync(ValidRevocationRequest request)
	{
		var payload = request.Token?.Payload;
		if (payload is { JwtId: {} jwtId, ExpiresAt: {} expiresAt })
			await tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt);

		return new TokenRevoked();
	}
}
