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
/// The tenant's token endpoint URL in each way a client allowed it as its assertion's audience may write it.
/// </summary>
/// <remarks>
/// Every spelling is compared as written: the path the transport serves the endpoint at on the issuer identifier's
/// scheme, host and port normalized as a URI authority is, the way discovery moves an endpoint onto the issuer, and on
/// them as the issuer identifier writes them, a default port or a host's case included. The issuer's authority rather
/// than the request's, because a request names its own host: taken from it, a caller presenting an assertion minted for
/// another server under the same path would name that server's host and match. Both spellings name this server alone.
/// </remarks>
internal static class TenantDefinitionExtensions
{
    /// <summary>
    /// The spellings for <paramref name="tenant"/>, or none where no transport resolves the path - a host running the
    /// core alone - or the endpoint is not mapped.
    /// </summary>
    /// <remarks>
    /// The resolver is read through a scope of its own, because it is scoped while authenticators are singletons; it
    /// reads the current request through the HTTP context accessor rather than through that scope.
    /// </remarks>
    /// <param name="tenant">The tenant whose issuer identifier the spellings are built on.</param>
    /// <param name="serviceProvider">Resolves where the transport serves the token endpoint.</param>
    public static string[] TokenEndpointSpellings(this TenantDefinition tenant, IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var resolved = scope.ServiceProvider.GetService<IOidcEndpointResolver>()?.Resolve(OidcEndpoints.Token);
        if (resolved is null)
            return [];

        return
        [
            resolved.OnAuthorityOf(tenant.Issuer).OriginalString,
            AuthorityAsWritten(tenant.Issuer) + resolved.AbsolutePath,
        ];
    }

    /// <summary>
    /// The scheme, host and port of <paramref name="issuer"/> exactly as its identifier writes them, without its path,
    /// which the resolved endpoint path already carries for a tenant served under one.
    /// </summary>
    private static string AuthorityAsWritten(Uri issuer)
    {
        var written = issuer.OriginalString;
        var hostStart = written.IndexOf(Uri.SchemeDelimiter, StringComparison.Ordinal) + Uri.SchemeDelimiter.Length;
        var pathStart = written.IndexOf('/', hostStart);
        return pathStart < 0 ? written : written[..pathStart];
    }
}
