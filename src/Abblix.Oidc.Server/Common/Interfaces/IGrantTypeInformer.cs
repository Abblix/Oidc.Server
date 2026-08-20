// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
