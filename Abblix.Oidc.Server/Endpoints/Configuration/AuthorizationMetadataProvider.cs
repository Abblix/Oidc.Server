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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Configuration;

/// <summary>
/// Provides authorization-related metadata by delegating to the authorization handler.
/// </summary>
public sealed class AuthorizationMetadataProvider(IAuthorizationHandler authorizationHandler)
	: IAuthorizationMetadataProvider
{
	/// <inheritdoc />
	public IEnumerable<string> ResponseTypesSupported => authorizationHandler.Metadata.ResponseTypesSupported;

	/// <inheritdoc />
	public IEnumerable<string> ResponseModesSupported => authorizationHandler.Metadata.ResponseModesSupported;

	/// <inheritdoc />
	public IEnumerable<string> PromptValuesSupported => authorizationHandler.Metadata.PromptValuesSupported;

	/// <inheritdoc />
	public IEnumerable<string> CodeChallengeMethodsSupported => authorizationHandler.Metadata.CodeChallengeMethodsSupported;

	/// <inheritdoc />
	public bool ClaimsParameterSupported => authorizationHandler.Metadata.ClaimsParameterSupported;

	/// <inheritdoc />
	public bool RequestParameterSupported => authorizationHandler.Metadata.RequestParameterSupported;
}
