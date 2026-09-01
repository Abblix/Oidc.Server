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
    /// The DEFAULT is every algorithm this library implements, not the RS256 the CAEP Interoperability
    /// Profile 1.0 draft 01 Section 2.6 requires, and the difference is deliberate. This verifier is
    /// shared: <c>AddBackChannelLogoutReceiver</c> resolves the same one, and an OIDC Logout Token is
    /// signed with whatever the client registered as its <c>id_token_signed_response_alg</c> - ES256 and
    /// PS256 are conformant and common there, and its producer is somebody else's provider, so a
    /// receiver has nothing to "keep in step" with. Defaulting to the profile's single algorithm would
    /// have refused every such token on upgrade, measured against the previous release.
    /// </para>
    /// <para>
    /// So a deployment that must be CAEP-conformant NARROWS this to RS256 deliberately, which is a line
    /// it can point at, rather than inheriting it from a default that also governs a protocol the
    /// profile says nothing about. Of the FAPI 2.0 direction this library offers PS256 and ES256; EdDSA
    /// it does not implement, so naming it here would name an algorithm nothing can use.
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
    /// The value is copied on assignment, because a caller holding the array it passed could otherwise
    /// add <c>none</c> to it afterwards, and an invariant a caller can break after assignment is not one.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">The set is empty, or contains <c>none</c>.</exception>
    public string[]? AllowedSigningAlgorithms
    {
        get => _allowedSigningAlgorithms;
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
    /// What <see cref="AllowedSigningAlgorithms"/> means when a host has set nothing: every signature
    /// algorithm this library implements.
    /// </summary>
    public static IReadOnlyList<string> DefaultSigningAlgorithms { get; } =
    [
        SigningAlgorithms.RS256, SigningAlgorithms.RS384, SigningAlgorithms.RS512,
        SigningAlgorithms.PS256, SigningAlgorithms.PS384, SigningAlgorithms.PS512,
        SigningAlgorithms.ES256, SigningAlgorithms.ES384, SigningAlgorithms.ES512,
    ];

    /// <summary>
    /// The algorithms in force: what the host set, or the default when it set nothing.
    /// </summary>
    internal string[] EffectiveSigningAlgorithms => _allowedSigningAlgorithms ?? [.. DefaultSigningAlgorithms];


}
