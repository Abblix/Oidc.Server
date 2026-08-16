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
    /// Where a named issuer's JWK Set document is, for issuers known when the host is composed.
    /// </summary>
    /// <remarks>
    /// Consulted first, and additive: two consumers in one host - a back-channel logout receiver
    /// and a Shared Signals receiver, say - each add their own issuer without knowing about the
    /// other. That is what a host cannot get right through <see cref="JwksUriSelector"/> alone: a
    /// single-valued delegate makes every consumer past the first compose a chain by hand, and one
    /// that forgets to call the previous delegate silently removes another issuer's keys - a token
    /// that used to verify starts failing its signature, which reads as an attack rather than as
    /// wiring.
    /// </remarks>
    public IDictionary<string, Uri> JwksUris { get; } = new Dictionary<string, Uri>(StringComparer.Ordinal);

    /// <summary>
    /// Answers where an issuer's JWK Set document is, for issuers whose location is learned at run
    /// time. Returning null means "not mine", and resolution carries on.
    /// </summary>
    /// <remarks>
    /// The escape hatch beside <see cref="JwksUris"/>, for a location that cannot be written down
    /// when the host is composed - a Shared Signals transmitter advertises its "jwks_uri" in the
    /// ssf-configuration document, and that value, not a convention, is authoritative for it.
    /// <para>
    /// Returning null rather than throwing is what keeps the sources composable: a delegate that
    /// threw for an issuer it did not recognise would also take out the well-known fallback for
    /// every other issuer, since nothing runs after it.
    /// </para>
    /// </remarks>
    public Func<string, Uri?>? JwksUriSelector { get; set; }

    /// <summary>
    /// Where this issuer's keys are fetched from: a named entry, then the selector, then the
    /// "{issuer}/.well-known/jwks.json" convention.
    /// </summary>
    /// <param name="issuer">The issuer whose JWK Set is wanted.</param>
    internal Uri? ResolveJwksUri(string issuer)
        => JwksUris.TryGetValue(issuer, out var mapped) ? mapped : JwksUriSelector?.Invoke(issuer);

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
