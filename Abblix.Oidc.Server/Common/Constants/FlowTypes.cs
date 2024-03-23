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
