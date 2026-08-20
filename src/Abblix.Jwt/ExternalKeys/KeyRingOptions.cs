// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Configuration of the key ring.
/// </summary>
public sealed class KeyRingOptions
{
    /// <summary>
    /// How long a newly minted key is published before the ring starts producing with it.
    /// </summary>
    /// <remarks>
    /// A consumer caches the published key set, so a key that starts signing the moment it appears will sign
    /// tokens that consumers with a warm cache cannot yet verify. Publishing first and producing later closes
    /// that window: by the time a key leads its algorithm, every consumer refreshing on the usual schedule has
    /// already seen it.
    ///
    /// The value is therefore a property of how long consumers cache, not of how often keys rotate. An hour
    /// covers the caching most providers and clients default to.
    /// </remarks>
    public TimeSpan KeyRolloverPropagation { get; set; } = TimeSpan.FromHours(1);
}
