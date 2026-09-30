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
    /// Every address <paramref name="tenant"/> is served at: its issuer's, and its mutual-TLS host under the
    /// issuer's path when it declares one.
    /// </summary>
    public static IEnumerable<TenantAddress> AllOf(TenantDefinition tenant)
    {
        var issuer = Of(tenant.Issuer);
        yield return issuer;

        if (tenant.MtlsBaseUri is { IsAbsoluteUri: true } mtls)
            yield return issuer with { Host = TenantHost.Normalize(mtls.Host) };
    }

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

    /// <summary>
    /// <paramref name="path"/> with every encoded slash in one case, the form both an issuer's path and a request
    /// path are compared in: RFC 3986 section 2.1 makes the case of an escape insignificant, and the server keeps
    /// an encoded slash as the client wrote it.
    /// </summary>
    /// <remarks>
    /// Used to compare, never to address: an encoded slash in the addresses built from a request stays as the
    /// client wrote it, since a client assertion's audience is compared with them exactly. The length never
    /// changes, so a position found in this form is the same position in the original.
    /// </remarks>
    public static string CanonicalPath(string path)
        => path.Replace(EncodedSlash, EncodedSlash, StringComparison.OrdinalIgnoreCase);

    private const string EncodedSlash = "%2F";

    private static string DecodePath(string escapedPath)
    {
        var decoded = new StringBuilder();
        var start = 0;
        int slash;
        while ((slash = escapedPath.IndexOf(EncodedSlash, start, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            decoded
                .Append(Uri.UnescapeDataString(escapedPath[start..slash]))
                .Append(escapedPath, slash, EncodedSlash.Length);
            start = slash + EncodedSlash.Length;
        }

        return decoded.Append(Uri.UnescapeDataString(escapedPath[start..])).ToString();
    }

    /// <summary>
    /// Whether <paramref name="path"/> is this address's path or goes on below it, compared by whole segments:
    /// <c>/tenants/acme</c> covers <c>/tenants/acme/connect/token</c> and not <c>/tenants/acme2</c>.
    /// </summary>
    public bool Covers(string path)
        => CanonicalPath(path).StartsWith(CanonicalPath(Path), StringComparison.Ordinal) &&
           (path.Length == Path.Length || path[Path.Length] == '/');

    /// <summary>
    /// This address with its path in the form it is compared in, so two addresses no request can tell apart are
    /// equal.
    /// </summary>
    public TenantAddress Canonical() => this with { Path = CanonicalPath(Path) };
}
