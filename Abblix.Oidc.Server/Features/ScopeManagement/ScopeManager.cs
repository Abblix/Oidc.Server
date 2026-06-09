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

using System.Collections;
using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ScopeManagement;

/// <summary>
/// In-memory <see cref="IScopeManager"/> that seeds the registry with the six OIDC Core §5.4
/// standard scopes (<c>openid</c>, <c>profile</c>, <c>email</c>, <c>address</c>, <c>phone</c>,
/// <c>offline_access</c>) and merges any host-defined scopes from
/// <see cref="OidcOptions.Scopes"/>. Lookups are case-sensitive (RFC 6749 §3.3 treats scope
/// values as case-sensitive strings) and host-defined scopes do not override the standard ones.
/// </summary>
/// <param name="options">The options containing OIDC configuration, including additional custom scopes.</param>
public class ScopeManager(IOptions<OidcOptions> options) : IScopeManager
{
    private readonly Dictionary<string, ScopeDefinition> _scopes = InitializeScopes(options);

    private static Dictionary<string, ScopeDefinition> InitializeScopes(IOptions<OidcOptions> options)
    {
        var scopes = new Dictionary<string, ScopeDefinition>(StringComparer.Ordinal);

        void Add(ScopeDefinition scope) => scopes.TryAdd(scope.Scope, scope);

        Add(StandardScopes.OpenId);
        Add(StandardScopes.Profile);
        Add(StandardScopes.Email);
        Add(StandardScopes.Address);
        Add(StandardScopes.Phone);
        Add(StandardScopes.OfflineAccess);

        if (options.Value.Scopes != null)
            Array.ForEach(options.Value.Scopes, Add);

        return scopes;
    }

    /// <summary>
    /// Attempts to retrieve the definition of a specified scope.
    /// </summary>
    /// <param name="scope">The scope identifier to retrieve the definition for.</param>
    /// <param name="definition">Outputs the <see cref="ScopeDefinition"/> if the scope exists, otherwise null.</param>
    /// <returns>True if the scope exists and the definition is retrieved, false otherwise.</returns>
    public bool TryGet(string scope, [MaybeNullWhen(false)] out ScopeDefinition definition)
        => _scopes.TryGetValue(scope, out definition);

    /// <summary>
    /// Iterates over all registered scope definitions in unspecified order.
    /// </summary>
    public IEnumerator<ScopeDefinition> GetEnumerator() => _scopes.Values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
