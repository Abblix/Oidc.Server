// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The one spelling a host name is compared in.
/// </summary>
/// <remarks>
/// A request can name one host several ways - with a trailing dot, in Unicode or in its ASCII form, in any
/// case - and a binding compared as written would be missed by all but one of them, letting a path choose
/// another tenant on a host bound to the first.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public static class TenantHost
{
    private static readonly IdnMapping Idn = new();

    /// <summary>
    /// <paramref name="host"/> in ASCII, in lower case, without a trailing dot.
    /// </summary>
    /// <remarks>
    /// A name that is not a valid internationalized host comes back only lowered and trimmed. It arrives in a
    /// request's Host header, where it is the caller's to write, and no binding can equal it, since every
    /// declared host is refused at startup unless it is a valid one.
    /// </remarks>
    public static string Normalize(string host)
    {
        var trimmed = host.TrimEnd('.').ToLowerInvariant();
        if (trimmed.Length == 0)
            return trimmed;

        try
        {
            return Idn.GetAscii(trimmed);
        }
        catch (ArgumentException)
        {
            return trimmed;
        }
    }

    /// <summary>
    /// Whether <paramref name="host"/> is a host name a tenant can be bound to: a valid, internationalized or
    /// ASCII, name with no port.
    /// </summary>
    public static bool IsBindable(string host)
    {
        if (string.IsNullOrEmpty(host) || host.Contains(':') || host.Contains('/'))
            return false;

        try
        {
            Idn.GetAscii(host.TrimEnd('.'));
            return Uri.CheckHostName(Normalize(host)) is UriHostNameType.Dns;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
