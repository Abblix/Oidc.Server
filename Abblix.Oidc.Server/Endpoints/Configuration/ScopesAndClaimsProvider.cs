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

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
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
