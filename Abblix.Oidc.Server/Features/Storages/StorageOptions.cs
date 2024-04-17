// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
//
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
//
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
//
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
//
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
//
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
//
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
