// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

	/// <summary>
	/// The <c>none</c> response type flow (OAuth 2.0 Multiple Response Type Encoding Practices section 4): the
	/// authorization request runs to completion but the response carries no authorization code and no
	/// tokens. A distinct non-zero value so it never collides with <c>default(FlowTypes)</c>, which the
	/// flow detector uses as its "no flow detected" sentinel; it does not combine with the token-part
	/// flags above.
	/// </summary>
	None = 1 << 2,
}
