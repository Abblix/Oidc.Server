// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client whose refresh token reuse policy is not one of the values the policy defines,
/// and warns of a client whose Reuse the rotation policy does not follow for every token.
/// </summary>
/// <remarks>
/// A configuration binder takes a number outside the defined values as it stands, so the client would pass startup
/// and fail the first token request that issues it a refresh token. Reuse for a public client not requiring DPoP is
/// served, but its tokens bound to no key rotate (RFC 9700 section 2.2.2), so the host is told rather than left to
/// believe they are reused. The settings are validated again for every request scope and a tenant store is read
/// again every period, so a client is warned of once, and again only after its setting stopped calling for it.
/// </remarks>
/// <param name="logger">Records each client whose Reuse is not followed for every token.</param>
public sealed partial class RefreshTokenReusePolicyCheck(ILogger<RefreshTokenReusePolicyCheck> logger) : ITenantsCheck
{
	private readonly ConcurrentDictionary<(string TenantId, string ClientId), bool> _warned = new();

	/// <inheritdoc />
	public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
	{
		foreach (var tenant in tenants)
			Warn(tenant);

		return TenantRefusal.EachOf(tenants, tenant => Failures(tenant.Clients));
	}

	/// <summary>
	/// Warns once of each client of <paramref name="tenant"/> that declares Reuse without requiring DPoP, and forgets a
	/// client that stops declaring it, so declaring it again is warned of again.
	/// </summary>
	private void Warn(TenantDefinition tenant)
	{
		var notFollowed = tenant.Clients
			.Where(RefreshTokenRotationPolicy.DeclaresReuseWithoutDPoP)
			.Select(client => client.ClientId)
			.ToHashSet(StringComparer.Ordinal);

		foreach (var gone in _warned.Keys.Where(key => key.TenantId == tenant.Id && !notFollowed.Contains(key.ClientId)))
			_warned.TryRemove(gone, out _);

		foreach (var clientId in notFollowed.Where(clientId => _warned.TryAdd((tenant.Id, clientId), true)))
			LogReuseNotFollowed(tenant.Id, clientId);
	}

	private static IEnumerable<string> Failures(IEnumerable<ClientInfo> clients)
		=> clients
			.Where(client => !Enum.IsDefined(client.RefreshToken.ReusePolicy))
			.Select(client =>
				$"The client '{client.ClientId}' has {nameof(RefreshTokenOptions.ReusePolicy)} " +
				$"{client.RefreshToken.ReusePolicy}, which is not one of " +
				$"{string.Join(", ", Enum.GetNames<RefreshTokenReusePolicy>())}.");
}
