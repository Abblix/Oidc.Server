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

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Constants;

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
        IEnumerable<string> scopes,
        ResourceDefinition[]? resources,
        string[]? allowedClientScopes,
        [MaybeNullWhen(false)] out ScopeDefinition[] scopeDefinitions,
        [MaybeNullWhen(true)] out string errorDescription)
    {
        scopeDefinitions = null;
        errorDescription = null;

        var scopeList = new List<ScopeDefinition>();

        // Create a hash set of resource scopes if resources are provided and not empty
        var resourceScopes = resources is { Length: > 0 }
            ? resources
                .SelectMany(rd => rd.Scopes, (_, sd) => sd.Scope)
                .ToHashSet(StringComparer.Ordinal)
            : null;

        foreach (var scope in scopes)
        {
            // Enforce the client's registered scope set: a client must not obtain a scope it was
            // never registered for (RFC 6749 §3.3 — the AS restricts scope by policy). Empty/null
            // means no restriction, matching the per-issuer allow-list of the JWT bearer grant.
            if (allowedClientScopes is { Length: > 0 } &&
                !allowedClientScopes.Contains(scope, StringComparer.Ordinal))
            {
                errorDescription = "The scope is not allowed for this client";
                return false;
            }

            // Check if the scope is recognized by the scope manager
            if (scopeManager.TryGet(scope, out var scopeDefinition))
            {
                scopeList.Add(scopeDefinition);
            }
            // Check if the scope is part of the resource scopes
            else if (resourceScopes != null && resourceScopes.Contains(scope))
            {
                // skip it
            }
            else
            {
                errorDescription = "The scope is not available";
                return false;
            }
        }

        scopeDefinitions = scopeList.ToArray();
        return true;
    }
}
