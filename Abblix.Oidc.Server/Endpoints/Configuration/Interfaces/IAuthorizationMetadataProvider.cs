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
}
