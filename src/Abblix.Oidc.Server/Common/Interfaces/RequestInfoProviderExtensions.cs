// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Reads the caller's address in the form a budget has to count it by.
/// </summary>
internal static class RequestInfoProviderExtensions
{
    /// <summary>
    /// The address this request came from, named so that one sender has one name, or null when the server
    /// cannot see an address at all.
    /// </summary>
    /// <remarks>
    /// Every budget counted per address goes through here, because the name decides whether two requests
    /// share one. A sender reaching a dual-stack server arrives as an IPv4 address over one socket and as
    /// the mapped IPv6 form over the other, so a name taken verbatim hands it one allowance per spelling.
    /// The name is the canonical printing, taken from the mapped form where there is one, which an
    /// identifier of the arrival interface on that form does not change.
    /// </remarks>
    /// <param name="requestInfoProvider">The provider naming the request being answered.</param>
    /// <returns>The address, in the form every budget counts by, or null when there is none.</returns>
    public static string? SourceName(this IRequestInfoProvider requestInfoProvider)
        => requestInfoProvider.RemoteIpAddress switch
        {
            null => null,
            { IsIPv4MappedToIPv6: true } mapped => mapped.MapToIPv4().ToString(),
            var source => source.ToString(),
        };
}
