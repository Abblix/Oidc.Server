// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Builds the discovery document served at <c>/.well-known/openid-configuration</c>
/// per OpenID Connect Discovery 1.0 section 3 and RFC 8414 (OAuth 2.0 Authorization Server Metadata).
/// </summary>
public interface IConfigurationHandler
{
	/// <summary>
	/// Builds the framework-agnostic discovery payload. Endpoint URLs are filled in by the
	/// hosting layer because they depend on routing.
	/// </summary>
	Task<ConfigurationResponse> HandleAsync();
}
