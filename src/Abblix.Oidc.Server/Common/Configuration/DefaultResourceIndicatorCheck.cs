// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant whose <see cref="TenantDefinition.DefaultResourceIndicator"/> would put an unusable value in
/// every access token's <c>aud</c> claim.
/// </summary>
/// <remarks>
/// Both refusals are contradictions the host cannot see at runtime, because the token still issues and only
/// the resource server rejects it - somewhere else, later, and reported as an invalid token rather than as a
/// misconfiguration here.
/// </remarks>
public sealed class DefaultResourceIndicatorCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, Failures);

    private static IEnumerable<string> Failures(TenantDefinition tenant)
    {
        if (tenant.DefaultResourceIndicator is not { } defaultResource)
            yield break;

        // RFC 8707 Section 2 requires a resource indicator to be an absolute URI, and a relative one could
        // never match a request either, so it would sit as a value nothing accepts.
        if (!defaultResource.IsAbsoluteUri)
        {
            yield return
                $"{nameof(TenantDefinition.DefaultResourceIndicator)} '{defaultResource}' must be an absolute URI " +
                "(RFC 8707 Section 2).";
            yield break;
        }

        // A default naming a resource this server does not know produces tokens whose audience no resource
        // server recognizes, and the request that would have named it explicitly is refused as
        // invalid_target - so the two paths would disagree about the same identifier.
        var known = tenant.Resources is { Length: > 0 } resources &&
                    Array.Exists(resources, resource => resource.Resource == defaultResource);
        if (!known)
        {
            yield return
                $"{nameof(TenantDefinition.DefaultResourceIndicator)} '{defaultResource}' is not among the " +
                $"declared {nameof(TenantDefinition.Resources)}. Register it there, or clear the default to keep " +
                "the client identifier as the audience.";
        }
    }
}
