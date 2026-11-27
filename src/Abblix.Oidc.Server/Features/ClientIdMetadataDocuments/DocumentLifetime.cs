// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// How long a fetched metadata document may be held.
/// </summary>
internal static class DocumentLifetime
{
    /// <summary>
    /// How long the response may be held: what its Cache-Control says, never longer than the host's maximum, and the
    /// host's minimum when it says nothing.
    /// </summary>
    /// <remarks>
    /// Section 6.2: the server "SHOULD respect HTTP cache headers [RFC9111]", the Expires header "need not be honored,
    /// since Cache-Control takes precedence", and it "SHOULD enforce a maximum effective cache duration regardless of
    /// the cache directives in the response" and "a minimum effective cache duration when none is otherwise
    /// indicated". The server is the only reader of what it holds, so the directives of a shared cache (s-maxage) are
    /// not its own.
    /// </remarks>
    public static TimeSpan Of(HttpResponseMessage response, ClientIdMetadataDocumentOptions settings)
    {
        var cacheControl = response.Headers.CacheControl;
        if (cacheControl is { NoStore: true } or { NoCache: true })
            return TimeSpan.Zero;

        if (cacheControl?.MaxAge is not { } maxAge)
            return Shortest(settings.MinimumCacheDuration, settings.MaximumCacheDuration);

        // The Age header says how much of that lifetime has already passed in a cache on the way
        var remaining = maxAge - (response.Headers.Age ?? TimeSpan.Zero);
        return remaining <= TimeSpan.Zero ? TimeSpan.Zero : Shortest(remaining, settings.MaximumCacheDuration);
    }

    private static TimeSpan Shortest(TimeSpan first, TimeSpan second) => first < second ? first : second;
}
