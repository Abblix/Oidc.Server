// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
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
	/// <returns>
	/// A task representing the asynchronous operation, which upon completion will return a <see cref="Result{TSuccess, TFailure}"/>
	/// containing either <see cref="TokenRevoked"/> on success or <see cref="OidcError"/> on failure.
	/// </returns>
	Task<Result<TokenRevoked, OidcError>> ProcessAsync(ValidRevocationRequest request);
}
