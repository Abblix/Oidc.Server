// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ScopeManagement;

/// <summary>
/// In-memory <see cref="IScopeManager"/> that seeds the registry with the six OIDC Core section 5.4
/// standard scopes (<c>openid</c>, <c>profile</c>, <c>email</c>, <c>address</c>, <c>phone</c>,
/// <c>offline_access</c>) and merges any host-defined scopes from
/// <see cref="TenantDefinition.Scopes"/>, one registry for each tenant. Lookups are case-sensitive (RFC 6749 section 3.3 treats scope
/// values as case-sensitive strings). A host-defined scope under a standard name extends that
/// scope: the claims it lists are added to the standard ones, so the standard claim set cannot be
/// narrowed by redefinition and the host's additions cannot be lost to it.
/// </summary>
/// <param name="scopes">The registry of each tenant.</param>
public class ScopeManager(IIssuerLocal<Dictionary<string, ScopeDefinition>> scopes) : IScopeManager
{
    private Dictionary<string, ScopeDefinition> ScopesFor(TenantDefinition tenant)
    {
        var definitions = tenant.Scopes;
        return scopes.GetOrCreate(tenant, definitions, () => InitializeScopes(definitions));
    }

    private static Dictionary<string, ScopeDefinition> InitializeScopes(ScopeDefinition[]? customScopes)
    {
        var scopes = new Dictionary<string, ScopeDefinition>(StringComparer.Ordinal);

        void Add(ScopeDefinition scope)
        {
            // Merging rather than replacing keeps both parties whole: the host cannot strip a claim
            // OIDC Core assigns to a standard scope, and the library cannot silently discard the
            // claims the host attached to it - which is what a plain TryAdd used to do.
            scopes[scope.Scope] = scopes.TryGetValue(scope.Scope, out var existing)
                ? existing with { ClaimTypes = [.. existing.ClaimTypes.Union(scope.ClaimTypes, StringComparer.Ordinal)] }
                : scope;
        }

        Add(StandardScopes.OpenId);
        Add(StandardScopes.Profile);
        Add(StandardScopes.Email);
        Add(StandardScopes.Address);
        Add(StandardScopes.Phone);
        Add(StandardScopes.OfflineAccess);

        if (customScopes != null)
            Array.ForEach(customScopes, Add);

        return scopes;
    }

    /// <summary>
    /// Attempts to retrieve the definition of a specified scope.
    /// </summary>
    /// <param name="tenant">The tenant whose scopes are searched.</param>
    /// <param name="scope">The scope identifier to retrieve the definition for.</param>
    /// <param name="definition">Outputs the <see cref="ScopeDefinition"/> if the scope exists, otherwise null.</param>
    /// <returns>True if the scope exists and the definition is retrieved, false otherwise.</returns>
    public bool TryGet(TenantDefinition tenant, string scope, [MaybeNullWhen(false)] out ScopeDefinition definition)
        => ScopesFor(tenant).TryGetValue(scope, out definition);

    /// <inheritdoc />
    /// <remarks>In unspecified order.</remarks>
    public IEnumerable<ScopeDefinition> ScopesOf(TenantDefinition tenant) => ScopesFor(tenant).Values;
}
