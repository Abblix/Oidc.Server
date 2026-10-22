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
    /// endpoint moved onto <paramref name="mtlsBaseUri"/>, when the issuer has a mutual-TLS host.
    /// </summary>
    /// <param name="document">The document naming the ordinary endpoints.</param>
    /// <param name="mtlsBaseUri">The scheme, host and port of the issuer's mutual-TLS host, or null without one.
    /// </param>
    public static ConfigurationResponse WithMtlsAliases(ConfigurationResponse document, Uri? mtlsBaseUri)
    {
        if (mtlsBaseUri is null)
            return document;

        return document with
        {
            MtlsEndpointAliases = new MtlsAliases
            {
                TokenEndpoint = Rebase(document.TokenEndpoint, mtlsBaseUri),
                RevocationEndpoint = Rebase(document.RevocationEndpoint, mtlsBaseUri),
                IntrospectionEndpoint = Rebase(document.IntrospectionEndpoint, mtlsBaseUri),
                UserInfoEndpoint = Rebase(document.UserInfoEndpoint, mtlsBaseUri),
                PushedAuthorizationRequestEndpoint = Rebase(document.PushedAuthorizationRequestEndpoint, mtlsBaseUri),
                BackChannelAuthenticationEndpoint = Rebase(document.BackChannelAuthenticationEndpoint, mtlsBaseUri),
                DeviceAuthorizationEndpoint = Rebase(document.DeviceAuthorizationEndpoint, mtlsBaseUri),
            },
        };
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
            ? Rebase(endpoint, new Uri(issuer.GetLeftPart(UriPartial.Authority)))
            : endpoint;

    private static bool SameHost(Uri endpoint, Uri mtlsBaseUri)
        => TenantHost.Normalize(endpoint.Host) == TenantHost.Normalize(mtlsBaseUri.Host);

    /// <summary>
    /// <paramref name="original"/>'s path on the scheme, host and port of <paramref name="host"/>, which carries no
    /// path of its own: a mutual-TLS host is refused with one, and an issuer's host is taken without its path.
    /// </summary>
    private static Uri? Rebase(Uri? original, Uri host)
        => original is null ? null : new Uri(host, original.AbsolutePath);
}
