// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserInfo;

namespace Abblix.Oidc.Server.Endpoints.Configuration;

/// <summary>
/// Aggregates metadata about supported scopes, claims, grants, and subject types.
/// </summary>
public sealed class ScopesAndClaimsProvider(
	IScopeClaimsProvider scopeClaimsProvider,
	IEnumerable<IGrantTypeInformer> grantTypeProviders,
	ISubjectTypeConverter subjectTypeConverter) : IScopesAndClaimsProvider
{
	private IEnumerable<string>? _grantTypesSupported;

	/// <inheritdoc />
	public IEnumerable<string> ScopesSupported => scopeClaimsProvider.ScopesSupported;

	/// <inheritdoc />
	public IEnumerable<string> ClaimsSupported => scopeClaimsProvider.ClaimsSupported;

	/// <inheritdoc />
	public IEnumerable<string> GrantTypesSupported => _grantTypesSupported ??= ComputeGrantTypes();

	/// <inheritdoc />
	public IEnumerable<string> SubjectTypesSupported => subjectTypeConverter.SubjectTypesSupported;

	/// <summary>
	/// Computes and caches the list of supported grant types by aggregating from all providers.
	/// </summary>
	private string[] ComputeGrantTypes() => grantTypeProviders
		.SelectMany(provider => provider.GrantTypesSupported)
		.Distinct()
		.ToArray();
}
