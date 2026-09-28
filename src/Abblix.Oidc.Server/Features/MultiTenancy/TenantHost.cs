// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The one spelling a host name is compared in.
/// </summary>
/// <remarks>
/// A request can name one host several ways - with a trailing dot, in Unicode or in its ASCII form, in any
/// case - and a tenant compared as written would be missed by all but one of them.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public static class TenantHost
{
    private static readonly IdnMapping Idn = new();

    /// <summary>
    /// <paramref name="host"/> in ASCII, in lower case, without a trailing dot; an IP address in its canonical
    /// form, an IPv6 one in brackets as a Host header carries it.
    /// </summary>
    /// <remarks>
    /// A name that is not a valid internationalized host comes back only lowered and trimmed. It arrives in a
    /// request's Host header, where it is the caller's to write, and no issuer's host can equal it.
    /// </remarks>
    public static string Normalize(string host)
    {
        var trimmed = host.TrimEnd('.').ToLowerInvariant();
        if (trimmed.Length == 0)
            return trimmed;

        if (trimmed.StartsWith('[') && trimmed.EndsWith(']') &&
            IPAddress.TryParse(trimmed[1..^1], out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return $"[{v6}]";
        }

        if (IPAddress.TryParse(trimmed, out var v4) && v4.AddressFamily == AddressFamily.InterNetwork)
            return v4.ToString();

        try
        {
            return Idn.GetAscii(trimmed);
        }
        catch (ArgumentException)
        {
            return trimmed;
        }
    }
}
