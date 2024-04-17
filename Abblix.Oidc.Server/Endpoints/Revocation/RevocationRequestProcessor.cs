// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;


namespace Abblix.Oidc.Server.Endpoints.Revocation;

/// <summary>
/// Processes revocation requests for tokens.
/// This class is responsible for handling the logic associated with revoking tokens, such as access tokens or refresh tokens.
/// </summary>
public class RevocationRequestProcessor : IRevocationRequestProcessor
{
	/// <summary>
	/// Initializes a new instance of the <see cref="RevocationRequestProcessor"/> class.
	/// Sets up the processor with a token registry which will be used for updating the status of the tokens.
	/// </summary>
	/// <param name="tokenRegistry">The token registry to be used by this processor for managing token statuses.</param>
	public RevocationRequestProcessor(ITokenRegistry tokenRegistry)
	{
		_tokenRegistry = tokenRegistry;
	}

	private readonly ITokenRegistry _tokenRegistry;

	/// <summary>
	/// Asynchronously processes a valid revocation request.
	/// This method handles the revocation of a specified token by changing its status to 'Revoked' in the token registry.
	/// The operation ensures that the token is no longer valid for any future requests.
	/// </summary>
	/// <param name="request">The revocation request to be processed. Contains information about the token to be revoked.</param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation, which upon completion will yield a <see cref="RevocationResponse"/>.
	/// The response signifies the outcome of the revocation process.
	/// </returns>
	public async Task<RevocationResponse> ProcessAsync(ValidRevocationRequest request)
	{
		var payload = request.Token?.Payload;
		if (payload is { JwtId: {} jwtId, ExpiresAt: {} expiresAt })
			await _tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt);

		return new TokenRevokedResponse();
	}
}
