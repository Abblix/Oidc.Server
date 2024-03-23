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
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;


/// <summary>
/// Defines the interface for handling specific types of authorization grants within an OAuth 2.0 or OpenID Connect
/// context. Implementations of this interface are responsible for processing authorization requests based on
/// the supported grant type, validating the request, and generating appropriate authorization responses.
/// </summary>
public interface IAuthorizationGrantHandler
{
	/// <summary>
	/// The grant types this handler is responsible for.
	/// </summary>
	IEnumerable<string> GrantTypesSupported { get; }

	/// <summary>
	/// Processes an authorization request asynchronously, validates the request against the supported grant type
	/// and generates a response indicating the authorization result.
	/// </summary>
	/// <param name="request">The authorization request containing required parameters for the grant type.</param>
	/// <param name="clientInfo">Client information associated with the request, used for validation and generating
	/// the response.</param>
	/// <returns>A task that when completed successfully, returns a GrantAuthorizationResult indicating the outcome
	/// of the authorization process.</returns>
	Task<GrantAuthorizationResult> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo);
}
