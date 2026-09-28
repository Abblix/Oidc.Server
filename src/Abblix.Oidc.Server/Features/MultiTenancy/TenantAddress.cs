// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Where a tenant is served: the host and path of its issuer.
/// </summary>
/// <remarks>
/// Scheme and port are left out: behind a proxy the request carries its own, and two issuers differing in
/// nothing else could not be told apart by a request.
/// </remarks>
/// <param name="Host">The issuer's host, as <see cref="TenantHost.Normalize"/> leaves it.</param>
/// <param name="Path">The issuer's path without a trailing slash; empty for an issuer at the root of its host.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed record TenantAddress(string Host, string Path)
{
    /// <summary>
    /// The address <paramref name="issuer"/> names.
    /// </summary>
    /// <remarks>
    /// The host is taken with the brackets an IPv6 address keeps in a Host header, and the path decoded as the
    /// server decodes a request path - every escape except an encoded slash, which would otherwise split a
    /// segment - since that is the form each is compared with.
    /// </remarks>
    public static TenantAddress Of(string issuer)
    {
        var uri = new Uri(issuer, UriKind.Absolute);
        return new TenantAddress(TenantHost.Normalize(uri.Host), DecodePath(uri.AbsolutePath).TrimEnd('/'));
    }

    private static string DecodePath(string escapedPath)
    {
        const string encodedSlash = "%2F";

        var decoded = new StringBuilder();
        var start = 0;
        int slash;
        while ((slash = escapedPath.IndexOf(encodedSlash, start, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            decoded
                .Append(Uri.UnescapeDataString(escapedPath[start..slash]))
                .Append(escapedPath, slash, encodedSlash.Length);
            start = slash + encodedSlash.Length;
        }

        return decoded.Append(Uri.UnescapeDataString(escapedPath[start..])).ToString();
    }

    /// <summary>
    /// Whether <paramref name="path"/> is this address's path or goes on below it, compared by whole segments:
    /// <c>/tenants/acme</c> covers <c>/tenants/acme/connect/token</c> and not <c>/tenants/acme2</c>.
    /// </summary>
    public bool Covers(string path)
        => path.StartsWith(Path, StringComparison.Ordinal) &&
           (path.Length == Path.Length || path[Path.Length] == '/');
}
