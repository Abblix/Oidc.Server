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

using System.Collections.Concurrent;

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
    /// <para>
    /// <b>Filled in code, never from a configuration file.</b> An issuer identifier is a URL, and
    /// the ':' in it is the configuration hierarchy delimiter - so an entry written in appsettings
    /// binds as nested sections and this map stays empty, with no exception and no log. Every
    /// issuer then falls through to the well-known convention, which is the same silent
    /// wrong-document outcome this map exists to prevent. Environment variables are worse, the
    /// '__' delimiter notwithstanding.
    /// </para>
    /// <para>
    /// Concurrent by construction, because the resolver reads it on the validation path while a
    /// host may still be adding to it - a receiver that learns an issuer at run time is exactly
    /// the case the selector below describes, and a plain dictionary written during a read is a
    /// torn read or a hang rather than an error.
    /// </para>
    /// </remarks>
    public IDictionary<string, Uri> JwksUris { get; } = new ConcurrentDictionary<string, Uri>(IssuerComparer.Instance);

    /// <summary>
    /// Answers where an issuer's JWK Set document is, for issuers whose location is learned at run
    /// time. Returning null means "not mine", and resolution carries on.
    /// </summary>
    /// <remarks>
    /// The escape hatch beside <see cref="JwksUris"/>, for a location that cannot be written down
    /// when the host is composed - a Shared Signals transmitter advertises its "jwks_uri" in the
    /// ssf-configuration document, and that value, not a convention, is authoritative for it.
    /// <para>
    /// Returning null rather than throwing is what lets the map and the convention run after it: a
    /// delegate that threw for an issuer it did not recognise would take out the fallback for every
    /// other issuer, since nothing runs past a throw. It does NOT make two selectors composable -
    /// this is one property, so a second consumer setting it discards the first, which is the whole
    /// reason the map above exists.
    /// </para>
    /// </remarks>
    public Func<string, Uri?>? JwksUriSelector { get; set; }

    /// <summary>
    /// Where this issuer's keys are fetched from: a named entry, then the selector, then the
    /// "{issuer}/.well-known/jwks.json" convention.
    /// </summary>
    /// <remarks>
    /// The map answers first because it is the host's own statement about a specific issuer, and a
    /// statement written down beats one computed - a host wanting run-time metadata to win leaves
    /// that issuer out of the map rather than putting it in both.
    /// <para>
    /// The issuer is normalised the same way for the map as for the convention. Matching the raw
    /// string here while the convention trims a trailing slash would make one method disagree with
    /// itself: a map keyed with the slash would miss a token whose "iss" carries none, and the miss
    /// falls through to the convention rather than failing - the wrong document, quietly.
    /// </para>
    /// </remarks>
    /// <param name="issuer">The issuer whose JWK Set is wanted.</param>
    internal Uri? ResolveJwksUri(string issuer)
        => JwksUris.TryGetValue(issuer, out var mapped) ? mapped : JwksUriSelector?.Invoke(issuer);

    /// <summary>The form an issuer is compared and composed in: without a trailing slash.</summary>
    /// <remarks>
    /// One definition, used by the map's comparer and by the well-known composition in the resolver.
    /// Two of them would be a guard and a branch disagreeing about the same fact.
    /// </remarks>
    internal static string NormaliseIssuer(string issuer) => issuer.TrimEnd('/');

    /// <summary>Compares issuers the way this whole type does: a trailing slash decides nothing.</summary>
    /// <remarks>
    /// A comparer rather than normalisation at the lookup, because the map is written by the host
    /// and read here: normalising one side only moves the mismatch rather than removing it, and the
    /// mismatch does not fail - it falls through to the well-known convention, which may serve a
    /// document that verifies nothing this issuer signed.
    /// </remarks>
    private sealed class IssuerComparer : IEqualityComparer<string>
    {
        public static readonly IssuerComparer Instance = new();

        public bool Equals(string? x, string? y)
            => string.Equals(x?.TrimEnd('/'), y?.TrimEnd('/'), StringComparison.Ordinal);

        public int GetHashCode(string obj) => NormaliseIssuer(obj).GetHashCode(StringComparison.Ordinal);
    }

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
