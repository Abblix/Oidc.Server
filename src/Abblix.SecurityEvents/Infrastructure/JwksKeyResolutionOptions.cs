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

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// How JWKS-based key resolution finds and refreshes issuers' keys.
/// </summary>
public sealed class JwksKeyResolutionOptions
{
    /// <summary>
    /// Maps an issuer to its JWK Set document's location. Null derives
    /// "{issuer}/.well-known/jwks.json". A Shared Signals receiver sets this, because a
    /// transmitter advertises its "jwks_uri" in the ssf-configuration document and that value,
    /// not a convention, is authoritative for it.
    /// </summary>
    public Func<string, Uri>? JwksUriSelector { get; set; }

    /// <summary>
    /// How long a fetched key set answers from cache before the next resolution refetches it.
    /// The hot path of validation performs no network I/O within this lifetime - the property
    /// the plan demands of the resolver.
    /// </summary>
    public TimeSpan CacheLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// The floor between rollover refetches. A token naming a "kid" the cached set lacks forces
    /// one refetch - that is how a rotation is noticed before the cache expires - but a flood of
    /// tokens with a bogus identifier must not turn that courtesy into hammering the issuer, so
    /// within this window the miss answers from cache.
    /// </summary>
    public TimeSpan RolloverRefetchCooldown { get; set; } = TimeSpan.FromSeconds(30);
}
