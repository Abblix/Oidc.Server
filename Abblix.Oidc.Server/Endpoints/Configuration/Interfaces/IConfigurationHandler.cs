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

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Builds the discovery document served at <c>/.well-known/openid-configuration</c>
/// per OpenID Connect Discovery 1.0 §3 and RFC 8414 (OAuth 2.0 Authorization Server Metadata).
/// </summary>
public interface IConfigurationHandler
{
	/// <summary>
	/// Builds the framework-agnostic discovery payload. Endpoint URLs are filled in by the
	/// hosting layer because they depend on routing.
	/// </summary>
	Task<ConfigurationResponse> HandleAsync();
}
