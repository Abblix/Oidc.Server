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
/// case - and a tenant compared as written would be missed by all but one of them.
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
    /// request's Host header, where it is the caller's to write, and no issuer's host can equal it.
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
}
