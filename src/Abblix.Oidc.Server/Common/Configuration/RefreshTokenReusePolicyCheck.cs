// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client whose refresh token reuse policy is not one of the values the policy defines.
/// </summary>
/// <remarks>
/// A configuration binder takes a number outside the defined values as it stands, so the client would pass startup
/// and fail the first token request that issues it a refresh token.
/// </remarks>
public sealed class RefreshTokenReusePolicyCheck : ITenantsCheck
{
	/// <inheritdoc />
	public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
		=> TenantRefusal.EachOf(tenants, tenant => Failures(tenant.Clients));

	private static IEnumerable<string> Failures(IEnumerable<ClientInfo> clients)
		=> clients
			.Where(client => !Enum.IsDefined(client.RefreshToken.ReusePolicy))
			.Select(client =>
				$"The client '{client.ClientId}' has {nameof(RefreshTokenOptions.ReusePolicy)} " +
				$"{client.RefreshToken.ReusePolicy}, which is not one of " +
				$"{string.Join(", ", Enum.GetNames<RefreshTokenReusePolicy>())}.");
}
