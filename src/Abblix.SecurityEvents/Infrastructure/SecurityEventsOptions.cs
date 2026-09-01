// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;
using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// What a host configures once about its security-event handling: the event dictionary, signing,
/// and - for a profile that weakens the default validation - the reasoned acknowledgement of that
/// weakening. The pipeline itself is composed through the service collection: the default steps
/// register as an ordinary family, and a consumer profile edits them in place through the live
/// composition cursor after <c>AddSecurityEvents</c>.
/// </summary>
public sealed class SecurityEventsOptions
{

    /// <summary>
    /// The event dictionary: which event identifier URIs deserialize into which payload models.
    /// An event dictionary package is a set of calls against this registry.
    /// </summary>
    public EventTypeRegistry Events { get; } = new();

    /// <summary>
    /// Supplies the private key each signing uses - the one thing a transmitter must configure
    /// and a pure receiver never does. Left null, resolving the signer fails loudly naming this
    /// property, instead of a transmitter discovering at first delivery that it signs nothing.
    /// </summary>
    public Func<CancellationToken, Task<JsonWebKey>>? SigningKeySource { get; set; }

    /// <summary>
    /// The signature algorithms this deployment will sign a security event token with and accept one
    /// under. RS256 alone by default, which is what the CAEP Interoperability Profile 1.0 Section 2.6
    /// requires.
    /// </summary>
    /// <remarks>
    /// One set for both directions on purpose. A deployment that widens what it accepts and not what it
    /// emits, or the reverse, has two policies to keep in step and no place that says they disagree; and
    /// a receiver is entitled to expect that what a transmitter accepts is what it is willing to produce.
    /// <para>
    /// Stated rather than inherited. Before this, the transmitter signed with whatever the configured key
    /// declared and the receiver accepted whatever the validator's default permitted, so neither side
    /// said what it was willing to use and the two could differ without anybody noticing.
    /// </para>
    /// <para>
    /// The profile's requirement is under discussion upstream and the FAPI 2.0 set is the likely
    /// direction, which is why this is a set a deployment can widen rather than a constant. Of that set
    /// this library can sign and verify PS256 and ES256; EdDSA it cannot, so widening to it would name an
    /// algorithm nothing here implements. What the set cannot contain is <c>none</c>: an unsigned
    /// security event is not a weaker
    /// signature but the absence of one, and a set that could hold it would make the receiver's
    /// <c>RequireSignedTokens</c> the only thing standing between a deployment and an unauthenticated
    /// event.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">The set is empty, or contains <c>none</c>.</exception>
    public IReadOnlySet<string> AllowedSigningAlgorithms
    {
        get => _allowedSigningAlgorithms;
        set
        {
            if (value is not { Count: > 0 })
            {
                throw new ArgumentException(
                    "A deployment that allows no signature algorithm can neither emit a security event "
                    + "token nor accept one, so an empty set is a configuration nobody meant.",
                    nameof(AllowedSigningAlgorithms));
            }

            if (value.Contains(SigningAlgorithms.None))
            {
                throw new ArgumentException(
                    $"'{SigningAlgorithms.None}' is not a signature algorithm and cannot be allowed here: "
                    + "an unsigned security event carries no statement about who issued it, so accepting "
                    + "one is accepting anybody's.",
                    nameof(AllowedSigningAlgorithms));
            }

            _allowedSigningAlgorithms = value;
        }
    }

    private IReadOnlySet<string> _allowedSigningAlgorithms =
        new HashSet<string>(StringComparer.Ordinal) { SigningAlgorithms.RS256 };


}
