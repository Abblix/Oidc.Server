// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Narrows the scope an access token carries to the scopes of the resources it is addressed to.
/// </summary>
/// <remarks>
/// RFC 8707 section 2.2: "To the extent possible, when issuing access tokens, the authorization server should
/// downscope the scope value associated with an access token to the value the respective resource is able to process
/// and needs to know." RFC 9068 section 5 asks that each scope string in a token naming several resources "can be
/// unambiguously correlated to a specific resource among the ones listed in the "aud" claim". A scope one of the
/// tenant's resources declares belongs to that resource, so it stays only on a token addressed to a resource declaring
/// it; a scope no resource declares belongs to none, and stays. The tenant's declarations decide, as they decide
/// <see cref="ResourceInference"/>. A token is addressed to a resource it names in its audience, whether named as a
/// resource (RFC 8707) or as an audience (RFC 8693) equal to the resource's identifier.
/// </remarks>
internal static class ResourceScopes
{
    /// <summary>
    /// <paramref name="context"/> with only the scopes the resources it names declare, and those no resource of
    /// <paramref name="tenant"/> declares.
    /// </summary>
    public static AuthorizationContext NarrowedToItsResources(this AuthorizationContext context, TenantDefinition tenant)
    {
        if (tenant.Resources is not { Length: > 0 } definitions)
            return context;

        Uri[] addressed = [.. context.Resources ?? [], .. AsResources(context.Audiences)];
        return context with
        {
            Scope = [.. context.Scope.Where(scope => BelongsTo(scope, definitions, addressed))],
        };
    }

    private static IEnumerable<Uri> AsResources(string[]? audiences)
    {
        foreach (var audience in audiences ?? [])
        {
            if (Uri.TryCreate(audience, UriKind.Absolute, out var resource))
                yield return resource;
        }
    }

    private static bool BelongsTo(string scope, ResourceDefinition[] definitions, Uri[] addressed)
    {
        var declaring = definitions
            .Where(definition => definition.Scopes.Any(declared => declared.Scope == scope))
            .ToArray();

        return declaring.Length == 0 || declaring.Any(definition => addressed.Contains(definition.Resource));
    }
}
