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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Represents OAuth 2.0 flow types.
/// </summary>
[Flags]
public enum FlowTypes
{
	/// <summary>
	/// When using the Authorization Code Flow, all tokens are returned from the Token Endpoint.
	/// The Authorization Code Flow returns an Authorization Code to the Client, which can then exchange it for an ID Token and an Access Token directly.
	/// This provides the benefit of not exposing any tokens to the User Agent and possibly other malicious applications with access to the User Agent.
	/// The Authorization Server can also authenticate the Client before exchanging the Authorization Code for an Access Token.
	/// The Authorization Code flow is suitable for Clients that can securely maintain a Client Secret between themselves and the Authorization Server.
	/// </summary>
	/// <remarks>https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth</remarks>
	AuthorizationCode = 1 << 0,

	/// <summary>
	/// When using the Implicit Flow, all tokens are returned from the Authorization Endpoint; the Token Endpoint is not used.
	/// The Implicit Flow is mainly used by Clients implemented in a browser using a scripting language.
	/// The Access Token and ID Token are returned directly to the Client, which may expose them to the End-User and applications
	/// that have access to the End-User's User Agent. The Authorization Server does not perform Client Authentication.
	/// </summary>
	/// <remarks>https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth</remarks>
	Implicit = 1 << 1,

	/// <summary>
	/// When using the Hybrid Flow, some tokens are returned from the Authorization Endpoint and others are returned from the Token Endpoint.
	/// The mechanisms for returning tokens in the Hybrid Flow are specified in OAuth 2.0 Multiple Response Type Encoding Practices.
	/// </summary>
	/// <remarks>https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowSteps</remarks>
	Hybrid = AuthorizationCode | Implicit,
}
