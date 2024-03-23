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

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;


namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Defines an interface for managing authorization codes in the OAuth 2.0 authorization framework.
/// </summary>
public interface IAuthorizationCodeService
{
	/// <summary>
	/// Asynchronously generates an authorization code for a given authorization session and context.
	/// </summary>
	/// <param name="authSession">The current authentication session containing user and session information.</param>
	/// <param name="context">The authorization context associated with the current authorization request.</param>
	/// <param name="clientInfo">Information about the client making the authorization request.</param>
	/// <returns>A task that represents the asynchronous operation, which upon completion will yield the generated
	/// authorization code as a string.</returns>
	Task<string> GenerateAuthorizationCodeAsync(
		AuthSession authSession,
		AuthorizationContext context,
		ClientInfo clientInfo);

	/// <summary>
	/// Asynchronously authorizes a user based on a provided authorization code.
	/// </summary>
	/// <param name="authorizationCode">The authorization code to be validated and processed.</param>
	/// <returns>A task representing the asynchronous operation, which upon completion will yield a
	/// <see cref="GrantAuthorizationResult"/> representing the outcome of the authorization process.</returns>
	Task<GrantAuthorizationResult> AuthorizeByCodeAsync(string authorizationCode);

	/// <summary>
	/// Asynchronously removes an authorization code from the system, typically after it has been used or is no
	/// longer valid.
	/// </summary>
	/// <param name="authorizationCode">The authorization code to be removed.</param>
	/// <returns>A task representing the asynchronous operation of removing the authorization code.</returns>
	Task RemoveAuthorizationCodeAsync(string authorizationCode);
}
