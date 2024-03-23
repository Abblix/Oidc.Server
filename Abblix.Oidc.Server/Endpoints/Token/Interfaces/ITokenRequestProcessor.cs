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

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Processes incoming token requests from clients, ensuring they are valid and authorized before issuing
/// the appropriate token response. Depending on the request type and granted permissions, the response can include
/// various types of tokens such as Access Tokens, Refresh Tokens and ID Tokens.
/// </summary>
/// <remarks>
/// This interface abstracts the core logic behind token issuance in compliance with OAuth 2.0 and OpenID Connect
/// standards. Implementations are responsible for validating the token request details, determining the types of tokens
/// to issue based on the request's scope and authorization, and generating a token response that conforms to
/// the protocol specifications. While the typical response includes an Access Token and, in the case of OpenID Connect,
/// an ID Token, the exact contents of the response may vary based on the request parameters and server policies.
/// </remarks>
public interface ITokenRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a validated and authorized token request, generating a token response.
	/// </summary>
	/// <param name="request">The validated token request from the client.</param>
	/// <returns>A task that resolves to a <see cref="TokenResponse"/>, encapsulating the tokens to be issued to
	/// the client.</returns>
	Task<TokenResponse> ProcessAsync(ValidTokenRequest request);
}
