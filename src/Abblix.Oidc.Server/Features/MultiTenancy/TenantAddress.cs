// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

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
    public static TenantAddress Of(string issuer)
    {
        var uri = new Uri(issuer, UriKind.Absolute);
        return new TenantAddress(TenantHost.Normalize(uri.IdnHost), uri.AbsolutePath.TrimEnd('/'));
    }

    /// <summary>
    /// Whether <paramref name="path"/> is this address's path or goes on below it, compared by whole segments:
    /// <c>/tenants/acme</c> covers <c>/tenants/acme/connect/token</c> and not <c>/tenants/acme2</c>.
    /// </summary>
    public bool Covers(string path)
        => path.StartsWith(Path, StringComparison.Ordinal) &&
           (path.Length == Path.Length || path[Path.Length] == '/');
}
