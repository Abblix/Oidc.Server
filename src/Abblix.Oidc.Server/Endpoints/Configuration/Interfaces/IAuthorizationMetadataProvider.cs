// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Provides authorization-related metadata for OpenID Connect discovery.
/// </summary>
public interface IAuthorizationMetadataProvider
{
	/// <summary>
	/// Lists the response types supported by the authorization endpoint.
	/// </summary>
	IEnumerable<string> ResponseTypesSupported { get; }

	/// <summary>
	/// Lists the response modes supported by the authorization endpoint.
	/// </summary>
	IEnumerable<string> ResponseModesSupported { get; }

	/// <summary>
	/// Lists the prompt values supported during authentication.
	/// </summary>
	IEnumerable<string> PromptValuesSupported { get; }

	/// <summary>
	/// Lists the code challenge methods supported for PKCE.
	/// </summary>
	IEnumerable<string> CodeChallengeMethodsSupported { get; }

	/// <summary>
	/// Indicates whether the claims parameter is supported in authorization requests.
	/// </summary>
	bool ClaimsParameterSupported { get; }

	/// <summary>
	/// Indicates whether the request parameter is supported in authorization requests.
	/// </summary>
	bool RequestParameterSupported { get; }

	/// <summary>
	/// Indicates whether the server includes the <c>iss</c> parameter in authorization responses per RFC 9207.
	/// </summary>
	bool AuthorizationResponseIssParameterSupported { get; }
}
