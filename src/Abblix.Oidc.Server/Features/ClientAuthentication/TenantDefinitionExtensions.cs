// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// The URL of one of the tenant's endpoints, the token or the backchannel authentication endpoint, in each way a client
/// allowed it as its assertion's audience may write it.
/// </summary>
/// <remarks>
/// Every spelling is compared as written: the path the transport serves the endpoint at on the issuer identifier's
/// scheme, host and port normalized as a URI authority is, the way discovery moves an endpoint onto the issuer, and on
/// them as the issuer identifier writes them, a default port or a host's case included. The issuer's authority rather
/// than the request's, because a request names its own host: taken from it, a caller presenting an assertion minted for
/// another server under the same path would name that server's host and match. Both spellings name this server alone.
/// The same two spellings on the tenant's mutual-TLS address name the endpoint's alias, which discovery publishes in
/// <c>mtls_endpoint_aliases</c> and a client doing mutual TLS "MUST use ... in preference to the endpoint URL of the
/// same name at the top level of metadata" (RFC 8705 section 5): to that client the alias is the endpoint URL.
/// </remarks>
internal static class TenantDefinitionExtensions
{
    /// <summary>
    /// The spellings of <paramref name="endpoint"/> for <paramref name="tenant"/>, or none where no transport resolves
    /// the path - a host running the core alone - or the endpoint is not mapped.
    /// </summary>
    /// <remarks>
    /// The resolver is read through a scope of its own, because it is scoped while authenticators are singletons; it
    /// reads the current request through the HTTP context accessor rather than through that scope.
    /// </remarks>
    /// <param name="tenant">The tenant whose issuer identifier and mutual-TLS address the spellings are built on.
    /// </param>
    /// <param name="serviceProvider">Resolves where the transport serves the endpoint.</param>
    /// <param name="endpoint">The endpoint whose URL is spelled.</param>
    public static string[] EndpointSpellings(
        this TenantDefinition tenant,
        IServiceProvider serviceProvider,
        OidcEndpoints endpoint)
    {
        using var scope = serviceProvider.CreateScope();
        var resolved = scope.ServiceProvider.GetService<IOidcEndpointResolver>()?.Resolve(endpoint);
        if (resolved is null)
            return [];

        return tenant.MtlsBaseUri is { } mtlsBaseUri
            ? [..Spellings(resolved, tenant.Issuer), ..Spellings(resolved, mtlsBaseUri)]
            : Spellings(resolved, tenant.Issuer);
    }

    /// <summary>
    /// The path of <paramref name="resolved"/> on the scheme, host and port of <paramref name="authority"/>, both
    /// normalized and as <paramref name="authority"/> writes them.
    /// </summary>
    private static string[] Spellings(Uri resolved, Uri authority) =>
    [
        resolved.OnAuthorityOf(authority).OriginalString,
        AuthorityAsWritten(authority) + resolved.AbsolutePath,
    ];

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
