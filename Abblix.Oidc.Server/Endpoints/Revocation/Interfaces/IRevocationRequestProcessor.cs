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

namespace Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;

/// <summary>
/// Represents the capability to handle token revocation requests.
/// The authorization server invalidates tokens immediately upon revocation, preventing their future use.
/// Depending on the server's policy, revoking a token may also affect related tokens and the underlying authorization grant.
/// If a refresh token is revoked and the server supports revocation of access tokens, associated access tokens should also be invalidated.
/// </summary>
/// <remarks>
/// For more details, refer to RFC 7009 Section 2.1: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
/// </remarks>
public interface IRevocationRequestProcessor
{
	/// <summary>
	/// Processes a token revocation request.
	/// This method is responsible for handling the request to revoke a token, ensuring that the token and any associated tokens are invalidated.
	/// </summary>
	/// <param name="request">The valid revocation request to be processed. It contains the token that needs to be revoked along with any relevant information.</param>
	/// <returns>A task representing the asynchronous operation, which upon completion will return a <see cref="RevocationResponse"/> indicating the outcome of the revocation process.</returns>
	Task<RevocationResponse> ProcessAsync(ValidRevocationRequest request);
}
