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
/// Places a tenant's endpoints in its discovery document on the host each belongs to: the mutual-TLS aliases
/// (RFC 8705 section 5) on the tenant's mutual-TLS host, and the ordinary endpoints on the issuer's host, whichever of
/// the two the document was fetched on. Both transport adapters build the document through it.
/// </summary>
internal static class MtlsEndpointAliasing
{
    /// <summary>
    /// Adds the mutual-TLS aliases of the endpoints a client authenticating with its certificate calls, each the
    /// endpoint moved onto <paramref name="mtlsBaseUri"/>, when the issuer has a mutual-TLS host and the document names
    /// at least one of those endpoints.
    /// </summary>
    /// <remarks>
    /// The alias block "consists of one or more endpoint parameters" (RFC 8705 section 5), so a document naming none
    /// of the endpoints, with them disabled or their paths hidden, carries no block rather than an empty one.
    /// </remarks>
    /// <param name="document">The document naming the ordinary endpoints.</param>
    /// <param name="mtlsBaseUri">The scheme, host and port of the issuer's mutual-TLS host, or null without one.
    /// </param>
    public static ConfigurationResponse WithMtlsAliases(ConfigurationResponse document, Uri? mtlsBaseUri)
    {
        if (mtlsBaseUri is null)
            return document;

        var aliases = new MtlsAliases
        {
            TokenEndpoint = Rebase(document.TokenEndpoint, mtlsBaseUri),
            RevocationEndpoint = Rebase(document.RevocationEndpoint, mtlsBaseUri),
            IntrospectionEndpoint = Rebase(document.IntrospectionEndpoint, mtlsBaseUri),
            UserInfoEndpoint = Rebase(document.UserInfoEndpoint, mtlsBaseUri),
            PushedAuthorizationRequestEndpoint = Rebase(document.PushedAuthorizationRequestEndpoint, mtlsBaseUri),
            BackChannelAuthenticationEndpoint = Rebase(document.BackChannelAuthenticationEndpoint, mtlsBaseUri),
            DeviceAuthorizationEndpoint = Rebase(document.DeviceAuthorizationEndpoint, mtlsBaseUri),
        };

        // Compared as a whole, so an alias added to the block counts without being listed here again
        return aliases == new MtlsAliases() ? document : document with { MtlsEndpointAliases = aliases };
    }

    /// <summary>
    /// An endpoint resolved on the issuer's mutual-TLS host, where the document was fetched, moved to the issuer's
    /// own host: a client without a certificate follows the ordinary endpoints, and only the aliases may name the host
    /// that demands one.
    /// </summary>
    /// <remarks>
    /// The host is compared as a tenant is resolved by it, so whatever request reaches the tenant on its mutual-TLS host
    /// is answered so. An issuer whose mutual-TLS host differs from its ordinary one only by port therefore names the
    /// ordinary endpoints on the issuer's host on either.
    /// </remarks>
    /// <param name="endpoint">The endpoint as resolved for the request.</param>
    /// <param name="issuer">The issuer the document describes.</param>
    /// <param name="mtlsBaseUri">The issuer's mutual-TLS host, or null without one.</param>
    public static Uri? OnIssuersHost(Uri? endpoint, Uri issuer, Uri? mtlsBaseUri)
        => endpoint is not null && mtlsBaseUri is not null && SameHost(endpoint, mtlsBaseUri)
            ? Rebase(endpoint, issuer)
            : endpoint;

    private static bool SameHost(Uri endpoint, Uri mtlsBaseUri)
        => TenantHost.Normalize(endpoint.Host) == TenantHost.Normalize(mtlsBaseUri.Host);

    /// <summary>
    /// <paramref name="original"/>'s path, exactly as resolved and still escaped, on the scheme, host and port of
    /// <paramref name="host"/>, whose own path is not used.
    /// </summary>
    /// <remarks>
    /// Joined as text rather than resolved as a reference: a resolved path opening with an empty segment is a
    /// network-path reference to RFC 3986 section 4.2 and would name a host.
    /// </remarks>
    private static Uri? Rebase(Uri? original, Uri host)
        => original is null ? null : new Uri(host.GetLeftPart(UriPartial.Authority) + original.AbsolutePath);
}
