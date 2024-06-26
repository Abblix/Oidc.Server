﻿// Abblix OIDC Server Library
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
public record SuccessfullyAuthenticated(
	AuthorizationRequest Model,
	string ResponseMode,
	string? SessionId,
	ICollection<string> AffectedClientIds)
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
