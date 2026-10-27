// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Tells an issuer this server serves apart from one it trusts, for the grants and registrations that accept a token
/// another issuer wrote and so read nothing this server records about its own tokens.
/// </summary>
internal static class TenantIssuers
{
    /// <summary>
    /// Whether <paramref name="first"/> and <paramref name="second"/> name one issuer: scheme and host compared without
    /// regard to case, port and path exactly, as RFC 3986 makes scheme and host case-insensitive and leaves the path
    /// case-sensitive.
    /// </summary>
    public static bool Same(Uri first, Uri second)
        => SameOrigin(first, second) && first.AbsolutePath == second.AbsolutePath;

    /// <summary>
    /// Whether <paramref name="issuer"/> is the issuer of a tenant <paramref name="catalog"/> serves, whose tokens
    /// this server issued and may have revoked.
    /// </summary>
    /// <remarks>
    /// The tenant is looked up at the address the catalog keeps it under, its path decoded as a request path is, so a
    /// path holding an escaped character finds it as a request to it does.
    /// </remarks>
    public static async Task<bool> ServesAsync(this ITenantCatalog catalog, string issuer, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var uri))
            return false;

        var address = TenantAddress.Of(uri);
        return await catalog.FindByAddressAsync(address.Host, address.Path, cancellationToken) is { } tenant &&
               Same(tenant.Issuer, uri);
    }

    private static bool SameOrigin(Uri first, Uri second)
        => string.Equals(first.Scheme, second.Scheme, StringComparison.OrdinalIgnoreCase) &&
           string.Equals(first.Host, second.Host, StringComparison.OrdinalIgnoreCase) &&
           first.Port == second.Port;
}
