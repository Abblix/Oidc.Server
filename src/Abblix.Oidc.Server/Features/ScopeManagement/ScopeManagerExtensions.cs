// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ScopeManagement;

/// <summary>
/// Provides extension methods for scope validation, leveraging a scope manager and resource definitions
/// to ensure the validity and permissibility of requested scopes.
/// </summary>
public static class ScopeManagerExtensions
{
    /// <summary>
    /// Validates the requested scopes against registered scope definitions and resource definitions to confirm
    /// their validity and authorization.
    /// This method ensures that scopes are either recognized by the scope manager or included in the resource
    /// definitions.
    /// </summary>
    /// <param name="scopeManager">The scope manager that maintains the definitions of scopes.</param>
    /// <param name="tenant">The tenant whose scopes the request is judged against.</param>
    /// <param name="scopes">A collection of scope identifiers to be validated.</param>
    /// <param name="resources">An optional array of <see cref="ResourceDefinition"/> objects to validate scopes
    /// against.</param>
    /// <param name="allowedClientScopes">The scopes the requesting client is allowed to request (its registered
    /// scope set). When non-empty, any requested scope outside this set is rejected. When null or empty, no
    /// per-client restriction is applied. Mirrors the per-issuer allow-list used by the JWT bearer grant.</param>
    /// <param name="scopeDefinitions">Outputs an array of <see cref="ScopeDefinition"/> objects if
    /// the validation is successful, otherwise null.</param>
    /// <param name="errorDescription">Outputs a string describing the reason for validation failure,
    /// otherwise null if the validation is successful.</param>
    /// <returns>True if all requested scopes are valid and permissible, false otherwise.</returns>
    public static bool Validate(
        this IScopeManager scopeManager,
        TenantDefinition tenant,
        IEnumerable<string> scopes,
        ResourceDefinition[]? resources,
        string[]? allowedClientScopes,
        [MaybeNullWhen(false)] out ScopeDefinition[] scopeDefinitions,
        [MaybeNullWhen(true)] out string errorDescription)
    {
        scopeDefinitions = null;
        errorDescription = null;

        var scopeList = new List<ScopeDefinition>();

        foreach (var scope in scopes)
        {
            // Enforce the client's registered scope set: a client must not obtain a scope it was
            // never registered for (RFC 6749 section 3.3 - the AS restricts scope by policy). Empty/null
            // means no restriction, matching the per-issuer allow-list of the JWT bearer grant.
            if (allowedClientScopes is { Length: > 0 } &&
                !allowedClientScopes.Contains(scope, StringComparer.Ordinal))
            {
                errorDescription = "The scope is not allowed for this client";
                return false;
            }

            if (!scopeManager.IsAvailable(tenant, scope, resources, out var scopeDefinition))
            {
                errorDescription = "The scope is not available";
                return false;
            }

            // A scope only a resource declares is carried by the resource it belongs to, not listed here
            if (scopeDefinition != null)
                scopeList.Add(scopeDefinition);
        }

        scopeDefinitions = scopeList.ToArray();
        return true;
    }

    /// <summary>
    /// Whether a request naming <paramref name="resources"/> may carry <paramref name="scope"/>: a scope
    /// <paramref name="tenant"/> knows, or one any of <paramref name="resources"/> declares.
    /// </summary>
    /// <param name="scopeManager">The scope manager that maintains the definitions of scopes.</param>
    /// <param name="tenant">The tenant whose scopes are searched.</param>
    /// <param name="scope">The scope identifier asked about.</param>
    /// <param name="resources">The resources whose declared scopes count as well.</param>
    /// <param name="definition">The tenant's definition of the scope; null for a scope only a resource declares.
    /// </param>
    /// <returns>True when the scope may be carried, false otherwise.</returns>
    internal static bool IsAvailable(
        this IScopeManager scopeManager,
        TenantDefinition tenant,
        string scope,
        IEnumerable<ResourceDefinition>? resources,
        out ScopeDefinition? definition)
    {
        if (scopeManager.TryGet(tenant, scope, out definition))
            return true;

        // TryGet promises nothing about its output when it finds nothing, and a host's replacement may leave it set
        definition = null;
        return (resources ?? []).Any(resource => resource.Scopes.Any(declared => declared.Scope == scope));
    }
}
