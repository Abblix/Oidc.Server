// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Redis;

/// <summary>
/// Where in Redis the server's entities are written.
/// </summary>
public sealed class RedisEntityStorageOptions
{
    /// <summary>
    /// Put in front of every key this store writes, so a Redis shared with other tenants or other
    /// applications does not collide on a name as ordinary as an authorization code.
    /// </summary>
    /// <remarks>
    /// Changing it after a deployment is running orphans whatever is already stored: the old entries
    /// keep their own expiry and go away unattended, but an authorization in flight at that moment is
    /// no longer findable, so its holder is told the code expired.
    /// </remarks>
    public string KeyPrefix { get; init; } = "abblix:oidc:";

    /// <summary>
    /// Which Redis database the entries live in. Negative means the one the connection was configured
    /// with, which is what a deployment naming a database in its connection string expects.
    /// </summary>
    public int Database { get; init; } = -1;
}
