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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Flags representing the various OpenID Connect (OIDC) endpoints that the provider can expose.
/// These flags enable fine-grained control over which endpoints are enabled or disabled.
/// </summary>
[Flags]
public enum OidcEndpoints
{
	/// <summary>
	/// All OIDC endpoints are available, covering the full range of OpenID Connect operations.
	/// </summary>
	All = Configuration | Keys | Authorize | Token | UserInfo | CheckSession | EndSession | Revocation | Register |
	      PushedAuthorizationRequest | BackChannelAuthentication,

	/// <summary>
	/// The configuration endpoint, used by clients to dynamically discover information about the OpenID Provider.
	/// This typically provides metadata such as available endpoints, supported grant types, and signing algorithms.
	/// </summary>
	Configuration = 1 << 0,

	/// <summary>
	/// The keys endpoint, which provides public keys for validating the signatures of issued tokens.
	/// It is essential for clients to verify the integrity and authenticity of tokens.
	/// </summary>
	Keys = 1 << 1,

	/// <summary>
	/// The authorization endpoint, where user authentication and consent is initiated.
	/// This is the entry point for most OpenID Connect flows, particularly for obtaining authorization codes.
	/// </summary>
	Authorize = 1 << 2,

	/// <summary>
	/// The token endpoint, used to exchange authorization codes for tokens such as access tokens and ID tokens.
	/// It also supports other grant types like client credentials and refresh tokens.
	/// </summary>
	Token = 1 << 3,

	/// <summary>
	/// The user info endpoint, where authenticated user claims are retrieved after a successful authentication process.
	/// It provides information such as the user's name, email, and other identity claims.
	/// </summary>
	UserInfo = 1 << 4,

	/// <summary>
	/// The check session endpoint, typically used in single sign-on (SSO) scenarios to monitor the user's session state.
	/// It helps in detecting if the user session is still active or if the user has logged out.
	/// </summary>
	CheckSession = 1 << 5,

	/// <summary>
	/// The end session endpoint, which allows clients to log the user out from the OpenID Provider.
	/// It is used to terminate the user's session and notify relying parties of the logout event.
	/// </summary>
	EndSession = 1 << 6,

	/// <summary>
	/// The revocation endpoint, where clients can revoke access or refresh tokens.
	/// This is a security measure to invalidate tokens that are no longer needed or in cases of token compromise.
	/// </summary>
	Revocation = 1 << 7,

	/// <summary>
	/// The introspection endpoint, where clients can check the status of a token (e.g., whether it is active or expired).
	/// It provides detailed information about the token such as its expiration time and associated scopes.
	/// </summary>
	Introspection = 1 << 7,

	/// <summary>
	/// The client registration endpoint, which allows dynamic registration of clients.
	/// Clients can use this endpoint to register themselves with the OpenID Provider, typically during setup.
	/// </summary>
	Register = 1 << 8,

	/// <summary>
	/// The pushed authorization request endpoint, where clients can pre-register authorization requests with the provider.
	/// It provides an additional layer of security in certain authorization flows.
	/// </summary>
	PushedAuthorizationRequest = 1 << 9,

	/// <summary>
	/// The backchannel authentication endpoint, used in CIBA (Client-Initiated Backchannel Authentication) flows.
	/// It allows clients to initiate out-of-band authentication requests, often via a separate user device.
	/// </summary>
	BackChannelAuthentication = 1 << 10,
}
