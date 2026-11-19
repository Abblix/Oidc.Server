// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Adds to a tenant's discovery document the mutual-TLS aliases (RFC 8705 section 5) of its endpoints, each the
/// alias <see cref="TenantEndpointAddresses"/> publishes. Both transport adapters build the document through it.
/// </summary>
internal static class MtlsEndpointAliasing
{
    /// <summary>
    /// Adds the mutual-TLS aliases of the endpoints a client authenticating with its certificate calls, each the
    /// endpoint on the tenant's mutual-TLS address, when the tenant has one and the document names
    /// at least one of those endpoints.
    /// </summary>
    /// <remarks>
    /// The alias block "consists of one or more endpoint parameters" (RFC 8705 section 5), so a document naming none
    /// of the endpoints, with them disabled or their paths hidden, carries no block rather than an empty one.
    /// </remarks>
    /// <param name="document">The document naming the ordinary endpoints.</param>
    /// <param name="tenant">The tenant the document describes, whose mutual-TLS address the aliases are on.</param>
    public static ConfigurationResponse WithMtlsAliases(ConfigurationResponse document, TenantDefinition tenant)
    {
        if (tenant.MtlsBaseUri is null)
            return document;

        var aliases = new MtlsAliases
        {
            TokenEndpoint = Alias(tenant, document.TokenEndpoint),
            RevocationEndpoint = Alias(tenant, document.RevocationEndpoint),
            IntrospectionEndpoint = Alias(tenant, document.IntrospectionEndpoint),
            UserInfoEndpoint = Alias(tenant, document.UserInfoEndpoint),
            PushedAuthorizationRequestEndpoint = Alias(tenant, document.PushedAuthorizationRequestEndpoint),
            BackChannelAuthenticationEndpoint = Alias(tenant, document.BackChannelAuthenticationEndpoint),
            DeviceAuthorizationEndpoint = Alias(tenant, document.DeviceAuthorizationEndpoint),
        };

        // Compared as a whole, so an alias added to the block counts without being listed here again
        return aliases == new MtlsAliases() ? document : document with { MtlsEndpointAliases = aliases };
    }

    private static Uri? Alias(TenantDefinition tenant, Uri? published)
        => published is null ? null : tenant.PublishedMtlsAlias(published);
}
