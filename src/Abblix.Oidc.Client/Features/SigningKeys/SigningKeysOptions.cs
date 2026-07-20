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

namespace Abblix.Oidc.Client.Features.SigningKeys;

/// <summary>
/// Configuration for reading the provider's signing keys.
/// </summary>
public sealed class SigningKeysOptions
{
    /// <summary>
    /// How long a fetched key set is reused before it is read again.
    /// </summary>
    public TimeSpan CacheLifetime { get; set; } = TimeSpan.FromHours(12);

    /// <summary>
    /// The shortest interval between two key-set reads triggered by a token naming an unknown key.
    /// </summary>
    /// <remarks>
    /// A provider rotates its keys whenever it likes, so a token signed with a key the client has not seen is
    /// normal and must trigger a re-read rather than a rejection. That re-read is driven by unauthenticated
    /// input, though: anyone can present a token naming a random key. Without a floor, a stream of such
    /// tokens turns this client into a load generator against its own provider. The interval bounds that to
    /// one read per window, no matter how many unknown keys arrive.
    ///
    /// The bound is per client instance, because the count that enforces it lives in memory. An application
    /// running N replicas therefore allows up to N reads per window, not one. That is usually fine, and it is
    /// deliberately not solved by making a base client depend on shared storage. An application that needs a
    /// bound across replicas registers its own <see cref="IIssuerSigningKeysProvider"/> backed by whatever it
    /// already shares.
    /// </remarks>
    public TimeSpan MinimumRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);
}
