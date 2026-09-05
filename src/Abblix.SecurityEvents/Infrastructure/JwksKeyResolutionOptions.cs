// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    /// other. Nothing here is a slot one consumer can occupy: a single-valued setting makes every
    /// consumer past the first compose a chain by hand, and one that forgets to call the previous
    /// link silently removes another issuer's keys - a token that used to verify starts failing its
    /// signature, which reads as an attack rather than as wiring.
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
    /// The selectors added so far, asked in order until one answers.
    /// </summary>
    /// <remarks>
    /// Read-only here because adding is what a consumer does: see
    /// <see cref="AddJwksUriSelector"/>, which is the only way in, so no consumer can occupy the
    /// place of another.
    /// </remarks>
    internal IReadOnlyCollection<Func<string, Uri?>> JwksUriSelectors => _jwksUriSelectors;

    private readonly ConcurrentQueue<Func<string, Uri?>> _jwksUriSelectors = new();

    /// <summary>
    /// Adds a way to answer where an issuer's JWK Set document is, for issuers whose location is
    /// learned at run time. Returning null means "not mine", and resolution carries on.
    /// </summary>
    /// <remarks>
    /// The escape hatch beside <see cref="JwksUris"/>, for a location that cannot be written down
    /// when the host is composed - a Shared Signals transmitter advertises its "jwks_uri" in the
    /// ssf-configuration document, and that value, not a convention, is authoritative for it.
    /// <para>
    /// Additive for the same reason the map is, and by the same reasoning: two receivers, each
    /// learning its own transmitter's metadata, are the ordinary case rather than an exotic one. A
    /// settable delegate would make the second one discard the first, and the loss shows up as a
    /// signature that stopped verifying.
    /// </para>
    /// <para>
    /// Answering null rather than throwing is what lets the selectors after it, and then the
    /// convention, still run: a delegate that threw for an issuer it did not recognise would take
    /// the fallback out for every other issuer, since nothing runs past a throw.
    /// </para>
    /// </remarks>
    /// <param name="selector">Answers for the issuers it knows, null for the rest.</param>
    public JwksKeyResolutionOptions AddJwksUriSelector(Func<string, Uri?> selector)
    {
        ArgumentNullException.ThrowIfNull(selector);

        _jwksUriSelectors.Enqueue(selector);
        return this;
    }

    /// <summary>
    /// Where this issuer's keys are fetched from: a named entry, then each selector in the order it
    /// was added, then the "{issuer}/.well-known/jwks.json" convention.
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
    {
        if (JwksUris.TryGetValue(issuer, out var mapped))
            return mapped;

        foreach (var selector in _jwksUriSelectors)
        {
            if (selector(issuer) is { } answered)
                return answered;
        }

        return null;
    }

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

        // Both halves normalise through the same method, because a comparer whose Equals and
        // GetHashCode disagree does not fail - it files an entry in one bucket and looks for it in
        // another, so the map reads as empty for a key that is in it.
        public bool Equals(string? x, string? y)
            => string.Equals(
                x is null ? null : NormaliseIssuer(x),
                y is null ? null : NormaliseIssuer(y),
                StringComparison.Ordinal);

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

    /// <summary>
    /// Asks the issuer where its keys are, instead of guessing. When no map entry and no selector
    /// answers for an issuer, the resolver reads "jwks_uri" out of that issuer's discovery document
    /// at "{issuer}/.well-known/openid-configuration" and fetches the keys from there.
    /// </summary>
    /// <remarks>
    /// Off by default because it changes where an unconfigured issuer's keys come from, and a host
    /// relying on the "{issuer}/.well-known/jwks.json" convention must not have that moved under it
    /// by an upgrade.
    /// <para>
    /// What it buys is that the location follows the provider. A hand-written jwks_uri is a snapshot,
    /// and the copies fail one-sidedly: move the key set at the provider and this receiver refuses
    /// every token, while the same application's sign-in keeps working because it re-reads discovery.
    /// The log then says the signature does not verify, which reads as a forged token rather than as
    /// a configuration value that aged out, and the two places that disagree are never named.
    /// </para>
    /// </remarks>
    public bool UseDiscoveryDocument { get; set; }
}
