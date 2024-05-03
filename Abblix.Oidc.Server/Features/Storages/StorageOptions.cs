// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
