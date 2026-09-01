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
    /// The signature algorithms this deployment will sign a security event token with, and accept one
    /// under.
    /// </summary>
    /// <remarks>
    /// One set for both directions on purpose. A deployment that widens what it accepts and not what it
    /// emits, or the reverse, has two policies to keep in step and no place that says they disagree.
    /// <para>
    /// The DEFAULT is RS256 alone, which two specifications independently arrive at: the CAEP
    /// Interoperability Profile 1.0 draft 01 Section 2.6 requires it of security events, and OpenID
    /// Back-Channel Logout 1.0 Section 2.6 names it as the default for a Logout Token. It is also what
    /// this server's own logout tokens carry unless a client registered otherwise, so the two ends of a
    /// deployment that uses only our own pieces agree without anybody configuring anything.
    /// </para>
    /// <para>
    /// WIDENING is the host's move, and the host that has to make it is the one that already knows why:
    /// this verifier is shared, so <c>AddBackChannelLogoutReceiver</c> resolves the same one, and a
    /// deployment whose clients registered ES256 or PS256 as their <c>id_token_signed_response_alg</c>
    /// must name those here. Of the FAPI 2.0 direction this library offers PS256 and ES256; EdDSA it
    /// does not implement, so naming that would name an algorithm nothing can use.
    /// </para>
    /// <para>
    /// The refusal such a host meets names the algorithm that was rejected AND the set that would have
    /// been accepted, so the way out is readable from the message with no configuration in front of
    /// you. It arrives as <c>SignatureInvalid</c>, which RFC 8935 Section 2.4 renders on the wire as
    /// <c>invalid_key</c> - a key "unacceptable to the SET Recipient", which is what this is.
    /// </para>
    /// <para>
    /// What the set cannot contain is <c>none</c>: an unsigned security event is not a weaker signature
    /// but the absence of one, and a set that could hold it would make the receiver's
    /// <c>RequireSignedTokens</c> the only thing standing between a deployment and an unauthenticated
    /// event.
    /// </para>
    /// <para>
    /// NULL means the default, and the default is deliberately not the property's initial value: the
    /// configuration binder reads whatever is there, ADDS the configured entries and writes the result
    /// back, so a deployment narrowing the list to ES256 would get ES256 alongside everything the
    /// default carried and would believe it had excluded the rest. Measured on both a set and an array -
    /// the binder unions either. With nothing there, what it writes back is exactly what was configured.
    /// <see cref="DefaultSigningAlgorithms"/> is public so a host can still read what null means.
    /// </para>
    /// <para>
    /// The value is copied in BOTH directions, and one direction alone is worth nothing: a caller holding
    /// the array it passed could add <c>none</c> to it afterwards, and a caller reading the property back
    /// could write into what it got. Both reach the resolved signer, which asks the array live - measured,
    /// a write through the getter made it sign PS256 under an RS256-only policy. An invariant a caller can
    /// break after assignment is not one, in either direction.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">The set is empty, or contains <c>none</c>.</exception>
    public string[]? AllowedSigningAlgorithms
    {
        get => _allowedSigningAlgorithms is { } algorithms ? [.. algorithms] : null;
        set
        {
            if (value is null)
            {
                _allowedSigningAlgorithms = null;
                return;
            }

            if (value.Length == 0)
            {
                throw new ArgumentException(
                    "A deployment that allows no signature algorithm can neither emit a security event "
                    + "token nor accept one, so an empty set is a configuration nobody meant.",
                    nameof(AllowedSigningAlgorithms));
            }

            if (Array.Exists(value, algorithm => algorithm == SigningAlgorithms.None))
            {
                throw new ArgumentException(
                    $"'{SigningAlgorithms.None}' is not a signature algorithm and cannot be allowed here: "
                    + "an unsigned security event carries no statement about who issued it, so accepting "
                    + "one is accepting anybody's.",
                    nameof(AllowedSigningAlgorithms));
            }

            _allowedSigningAlgorithms = [.. value];
        }
    }

    private string[]? _allowedSigningAlgorithms;

    /// <summary>
    /// What <see cref="AllowedSigningAlgorithms"/> means when a host has set nothing: RS256 alone.
    /// </summary>
    public static IReadOnlyList<string> DefaultSigningAlgorithms { get; } = [SigningAlgorithms.RS256];

    /// <summary>
    /// The algorithms in force: what the host set, or the default when it set nothing.
    /// </summary>
    internal string[] EffectiveSigningAlgorithms => _allowedSigningAlgorithms ?? [.. DefaultSigningAlgorithms];


}
