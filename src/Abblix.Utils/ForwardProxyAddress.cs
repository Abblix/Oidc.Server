// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Judges the address of a forward proxy a deployment names for <see cref="AddressValidatingHttpMessageHandler"/>,
/// so every setting naming one is refused at startup for the same reasons rather than at the first request.
/// </summary>
public static class ForwardProxyAddress
{
    /// <summary>
    /// The schemes the platform's HTTP transport reaches a proxy by; any other is refused by it at the first request.
    /// </summary>
    private static readonly string[] SupportedSchemes = ["http", "https", "socks4", "socks4a", "socks5", "socks5h"];

    /// <summary>
    /// Why <paramref name="proxy"/> cannot name a forward proxy, or null when it can.
    /// </summary>
    /// <param name="proxy">The proxy address a setting holds.</param>
    /// <remarks>
    /// An address names only a scheme, a host and a port, and user information when the proxy asks for credentials:
    /// a path, a query or a fragment would be ignored by the transport, so a setting carrying one says more than it
    /// does.
    /// </remarks>
    public static string? WhyRefused(Uri proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (!proxy.IsAbsoluteUri)
            return $"the proxy address '{proxy}' must be an absolute URI naming a scheme and a host";

        if (!SupportedSchemes.Contains(proxy.Scheme, StringComparer.OrdinalIgnoreCase))
        {
            return $"the proxy address '{proxy}' must use one of the schemes {string.Join(", ", SupportedSchemes)}";
        }

        if (proxy.AbsolutePath != "/" || proxy.Query.Length > 0 || proxy.Fragment.Length > 0)
            return $"the proxy address '{proxy}' must carry no path, query or fragment";

        // A SOCKS scheme has no default port, so without one the transport refuses every request
        if (proxy.Port < 0)
            return $"the proxy address '{proxy}' must name a port";

        return null;
    }
}
