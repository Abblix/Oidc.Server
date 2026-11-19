// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Factory, the single owner of a tenant endpoint's addresses: the one discovery publishes, the mutual-TLS alias it
/// publishes beside it, and the spellings the JWT bearer grant and client authentication accept as that endpoint.
/// Each starts from the path the transport resolves the endpoint at, tenant path base included, and takes its scheme,
/// host and port from the tenant, never from the request.
/// </summary>
/// <remarks>
/// The tenant's authority rather than the request's, because a tenant is found by its host alone, port and case aside:
/// built on the request, an address would name whatever port or case the caller sent, and an assertion minted for
/// another service on that host would match. Every spelling is compared as written (RFC 3986 section 6.2.1, as RFC 10070
/// section 4 prescribes): the published address, the path on the issuer's authority normalized as a URI authority is,
/// and the same path on the authority exactly as the issuer writes it, a default port or a host's case included. Both
/// name this server alone. The same two on the tenant's mutual-TLS address name the endpoint's alias, which discovery
/// publishes in <c>mtls_endpoint_aliases</c> and a client doing mutual TLS "MUST use ... in preference to the endpoint
/// URL of the same name at the top level of metadata" (RFC 8705 section 5): to that client the alias is the endpoint
/// URL.
/// </remarks>
internal static class TenantEndpointAddresses
{
    /// <summary>
    /// The address discovery publishes for the endpoint the transport resolved at <paramref name="resolved"/>: its path
    /// on the issuer's scheme, host and port, normalized.
    /// </summary>
    /// <param name="tenant">The tenant whose issuer identifier the address is built on.</param>
    /// <param name="resolved">The endpoint as the transport resolves it for the request.</param>
    public static Uri Published(this TenantDefinition tenant, Uri resolved) => resolved.OnAuthorityOf(tenant.Issuer);

    /// <summary>
    /// The mutual-TLS alias discovery publishes for the endpoint at <paramref name="resolved"/>: its path on the
    /// tenant's mutual-TLS address, normalized, or null for a tenant without one.
    /// </summary>
    /// <param name="tenant">The tenant whose mutual-TLS address the alias is built on.</param>
    /// <param name="resolved">The endpoint as resolved or as published; only its path is used.</param>
    public static Uri? PublishedMtlsAlias(this TenantDefinition tenant, Uri resolved)
        => tenant.MtlsBaseUri is { } mtlsBaseUri ? resolved.OnAuthorityOf(mtlsBaseUri) : null;

    /// <summary>
    /// The spellings of <paramref name="endpoint"/> an assertion may name as its audience, or none where no transport
    /// resolves the path - a host running the core alone - or the endpoint is not mapped.
    /// </summary>
    /// <remarks>
    /// The resolver is read through a scope of its own, because it is scoped while its callers are singletons; it reads
    /// the current request through the HTTP context accessor rather than through that scope.
    /// </remarks>
    /// <param name="tenant">The tenant whose issuer identifier and mutual-TLS address the spellings are built on.
    /// </param>
    /// <param name="serviceProvider">Resolves where the transport serves the endpoint.</param>
    /// <param name="endpoint">The endpoint whose URL is spelled.</param>
    public static string[] AcceptedSpellings(
        this TenantDefinition tenant,
        IServiceProvider serviceProvider,
        OidcEndpoints endpoint)
    {
        using var scope = serviceProvider.CreateScope();
        var resolved = scope.ServiceProvider.GetService<IOidcEndpointResolver>()?.Resolve(endpoint);
        return resolved is null ? [] : tenant.AcceptedSpellings(resolved);
    }

    /// <summary>
    /// The spellings of the endpoint at <paramref name="resolved"/> an assertion may name as its audience: the
    /// published address first, then the path on the issuer's authority as the issuer writes it, and the same two on
    /// the tenant's mutual-TLS address where it has one.
    /// </summary>
    /// <param name="tenant">The tenant whose issuer identifier and mutual-TLS address the spellings are built on.
    /// </param>
    /// <param name="resolved">The endpoint as the transport resolves it for the request.</param>
    public static string[] AcceptedSpellings(this TenantDefinition tenant, Uri resolved)
    {
        string[] onTheIssuer =
        [
            tenant.Published(resolved).OriginalString,
            AuthorityAsWritten(tenant.Issuer) + resolved.AbsolutePath,
        ];

        return tenant is { MtlsBaseUri: { } mtlsBaseUri } && tenant.PublishedMtlsAlias(resolved) is { } alias
            ? [..onTheIssuer, alias.OriginalString, AuthorityAsWritten(mtlsBaseUri) + resolved.AbsolutePath]
            : onTheIssuer;
    }

    /// <summary>
    /// The scheme, host and port of <paramref name="authority"/> exactly as it writes them, without its path, which
    /// the resolved endpoint path already carries for a tenant served under one.
    /// </summary>
    private static string AuthorityAsWritten(Uri authority)
    {
        var written = authority.OriginalString;
        var hostStart = written.IndexOf(Uri.SchemeDelimiter, StringComparison.Ordinal) + Uri.SchemeDelimiter.Length;
        var pathStart = written.IndexOf('/', hostStart);
        return pathStart < 0 ? written : written[..pathStart];
    }
}
