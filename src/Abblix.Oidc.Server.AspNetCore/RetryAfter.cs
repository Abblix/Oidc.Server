// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Writes the <c>Retry-After</c> header for every refusal that names an interval - a key custodian that is
/// temporarily unable, a caller over its budget of requests - in both the MVC and Minimal API adapters.
/// </summary>
public static class RetryAfter
{
    /// <summary>
    /// Renders an interval as the header states it.
    /// </summary>
    /// <remarks>
    /// Retry-After counts whole seconds (RFC 9110 section 10.2.3), and rounding up is what keeps the advice honest:
    /// a client told to wait less than the server asked for arrives at the same refusal.
    /// </remarks>
    /// <param name="interval">How long the caller should wait.</param>
    /// <returns>The header value, in whole seconds.</returns>
    public static string HeaderValue(TimeSpan interval)
        => ((long)Math.Ceiling(interval.TotalSeconds)).ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Tells the caller how long the refusal lasts.
    /// </summary>
    /// <param name="response">The HTTP response to modify.</param>
    /// <param name="interval">How long the caller should wait.</param>
    public static void SetRetryAfter(this HttpResponse response, TimeSpan interval)
        => response.Headers.RetryAfter = HeaderValue(interval);
}
