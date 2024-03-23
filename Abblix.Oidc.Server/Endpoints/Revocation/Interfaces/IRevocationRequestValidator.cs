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

using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;

/// <summary>
/// Represents the capability to validate revocation requests.
/// The authorization server validates client credentials (for confidential clients) and checks if the token was issued
/// to the requesting client. If validation fails, the request is refused, and an error message is provided to
/// the client by the authorization server.
/// </summary>
public interface IRevocationRequestValidator
{
	/// <summary>
	/// Validates a revocation request.
	/// </summary>
	/// <param name="revocationRequest">The revocation request to be validated.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>A task representing the asynchronous operation with the validation result.</returns>
	Task<RevocationRequestValidationResult> ValidateAsync(
		RevocationRequest revocationRequest,
		ClientRequest clientRequest);
}
