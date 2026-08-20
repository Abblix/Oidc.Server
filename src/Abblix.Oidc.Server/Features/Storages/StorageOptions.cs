// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides configuration settings for cache entry behaviors in storage operations.
/// </summary>
public record StorageOptions
{
    /// <summary>
    /// The absolute expiration date and time for the cache entry. If set, the entry will expire and be removed
    /// from the cache at this specific date and time.
    /// </summary>
    public DateTimeOffset? AbsoluteExpiration { get; init; }

    /// <summary>
    /// The absolute expiration time relative to now. If set, the entry will expire after the specified duration
    /// from the time it was added or updated.
    /// </summary>
    public TimeSpan? AbsoluteExpirationRelativeToNow { get; init; }

    /// <summary>
    /// The sliding expiration time. If set, the expiration time for the cache entry will be extended by this amount
    /// each time the entry is accessed, preventing the entry from expiring if it is frequently accessed.
    /// </summary>
    public TimeSpan? SlidingExpiration { get; init; }
}
