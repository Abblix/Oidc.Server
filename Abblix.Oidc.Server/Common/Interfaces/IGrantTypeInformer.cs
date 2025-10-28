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

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Provides information about OAuth 2.0 grant types supported by a component.
/// Components implementing this interface can be registered in dependency injection
/// to contribute their supported grant types to the OpenID Connect discovery endpoint.
/// </summary>
/// <remarks>
/// This interface enables the discovery endpoint to automatically aggregate all supported
/// grant types from various components (authorization endpoint handlers, token endpoint handlers, etc.)
/// without requiring manual configuration.
/// </remarks>
public interface IGrantTypeInformer
{
	/// <summary>
	/// The grant types supported by this component, as defined in OAuth 2.0 and OpenID Connect specifications.
	/// </summary>
	/// <remarks>
	/// Common grant types include:
	/// <list type="bullet">
	/// <item><description>"authorization_code" - Authorization Code Grant</description></item>
	/// <item><description>"implicit" - Implicit Grant</description></item>
	/// <item><description>"refresh_token" - Refresh Token Grant</description></item>
	/// <item><description>"client_credentials" - Client Credentials Grant</description></item>
	/// <item><description>"password" - Resource Owner Password Credentials Grant</description></item>
	/// </list>
	/// </remarks>
	IEnumerable<string> GrantTypesSupported { get; }
}
