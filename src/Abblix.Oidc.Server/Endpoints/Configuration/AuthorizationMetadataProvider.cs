// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Configuration;

/// <summary>
/// Provides authorization-endpoint metadata for discovery, computed directly from the registered response
/// builders. Deliberately does not depend on <see cref="IAuthorizationHandler"/>: resolving the handler just to
/// read metadata would also construct its request-time dependencies (the JARM response encoder and its crypto
/// graph), which the discovery path must not do.
/// </summary>
/// <param name="responseBuilders">The registered response builders the supported response types are derived from.</param>
public sealed class AuthorizationMetadataProvider(IEnumerable<IAuthorizationResponseBuilder> responseBuilders)
	: IAuthorizationMetadataProvider
{
	private readonly AuthorizationEndpointMetadata _metadata = AuthorizationEndpointMetadataFactory.Create(responseBuilders);

	/// <inheritdoc />
	public IEnumerable<string> ResponseTypesSupported => _metadata.ResponseTypesSupported;

	/// <inheritdoc />
	public IEnumerable<string> ResponseModesSupported => _metadata.ResponseModesSupported;

	/// <inheritdoc />
	public IEnumerable<string> PromptValuesSupported => _metadata.PromptValuesSupported;

	/// <inheritdoc />
	public IEnumerable<string> CodeChallengeMethodsSupported => _metadata.CodeChallengeMethodsSupported;

	/// <inheritdoc />
	public bool ClaimsParameterSupported => _metadata.ClaimsParameterSupported;

	/// <inheritdoc />
	public bool RequestParameterSupported => _metadata.RequestParameterSupported;

	/// <inheritdoc />
	public bool AuthorizationResponseIssParameterSupported { get; init; } = true;
}
