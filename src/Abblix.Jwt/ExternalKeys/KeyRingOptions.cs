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
