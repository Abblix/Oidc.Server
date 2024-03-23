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

using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Represents a successful authentication response, encapsulating details about the outcome
/// of an authentication request, including any tokens issued as a result.
/// </summary>
/// <param name="Model">The original authorization request that led to this successful authentication.</param>
/// <param name="ResponseMode">Specifies how the result of the authentication should be returned to the client.</param>
/// <param name="SessionId">An optional session identifier that may be used for session management.</param>
/// <param name="AffectedClientIds"> Identifiers of the clients that are affected by or related to this authentication
/// process.</param>
public record SuccessfullyAuthenticated(AuthorizationRequest Model, string ResponseMode, string? SessionId, string[] AffectedClientIds)
	: AuthorizationResponse(Model)
{
	/// <summary>
	/// An authorization code that can be exchanged for tokens. This code is issued only if
	/// the authentication request was successful and the response type requested an authorization code.
	/// </summary>
	public string? Code { get; set; }

	/// <summary>
	/// The type of token issued, typically "Bearer", indicating how the issued token may be used.
	/// This property is populated if an access token is issued as part of the authentication response.
	/// </summary>
	public string? TokenType { get; set; }

	/// <summary>
	/// The access token issued as part of the authentication response, encoded in a format suitable for transmission.
	/// Access tokens are credentials used to access protected resources.
	/// </summary>
	public EncodedJsonWebToken? AccessToken { get; set; }

	/// <summary>
	/// The ID token issued as part of the authentication response, providing identity information about the user.
	/// Encoded in a format suitable for transmission.
	/// </summary>
	public EncodedJsonWebToken? IdToken { get; set; }

	/// <summary>
	/// An optional state parameter reflecting the session state. This can be used to represent the state of the user's
	/// session at the authorization server and may be used for managing session continuity and logout.
	/// </summary>
	public string? SessionState { get; set; }
}
