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

using Abblix.Utils;

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
	Task<Result<TokenRevoked, RevocationError>> ProcessAsync(ValidRevocationRequest request);
}
