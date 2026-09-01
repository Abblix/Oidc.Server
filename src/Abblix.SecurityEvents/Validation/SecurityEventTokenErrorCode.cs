// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Validation;

/// <summary>
/// Names the ways a SET can fail validation.
/// </summary>
/// <remarks>
/// The codes are coarse on purpose: they distinguish what a RECEIVER does differently - alert on
/// confusion, refetch keys on a key miss, drop and log on staleness - not every sentence of the
/// specification. The human-readable half lives in
/// <see cref="SecurityEventTokenValidationError.Description"/>. A custom step reports its own
/// failure through <see cref="Custom"/> plus a description, which is what keeps this enum from
/// growing a member per consumer.
/// </remarks>
public enum SecurityEventTokenErrorCode
{
    /// <summary>
    /// The compact serialization does not parse: wrong segment count, undecodable segment, or
    /// JSON that is not what the segment must hold.
    /// </summary>
    MalformedToken,

    /// <summary>
    /// The token is a JWT but not a SET, or a SET pretending otherwise: the "typ" header names a
    /// different type, or the claims carry "exp" - the shape RFC 8417 Section 4 warns is another
    /// kind of token in a SET's clothing, or the reverse.
    /// </summary>
    TokenConfusion,

    /// <summary>
    /// The "events" claim is absent, not a JSON object, or empty (RFC 8417 Section 2.2).
    /// </summary>
    MissingEvents,

    /// <summary>
    /// The "iss" claim is absent or names an issuer this receiver does not accept events from.
    /// </summary>
    UnknownIssuer,

    /// <summary>
    /// The token's signature is not one this receiver will act on: it did not verify under the issuer's
    /// keys, or the algorithm it was made with is one the receiver refuses.
    /// </summary>
    /// <remarks>
    /// A property rather than a list of causes, because the list is the JWT core's and grows without
    /// this file: an absent <c>alg</c>, one outside the RFC 7518 taxonomy and an unsigned token all
    /// arrive here too. What they share is what these codes actually distinguish - none of them is
    /// healed by refetching the issuer's keys, which is the whole of what <see cref="KeyNotFound"/>
    /// means. On the wire that is <c>invalid_key</c>, which RFC 8935 Section 2.4 defines as a key
    /// "invalid or otherwise unacceptable to the SET Recipient" - wide enough for every one of them.
    /// <para>
    /// WHICH of them happened is in <see cref="SecurityEventTokenValidationError.Description"/>, which
    /// the core writes at the branch that knows: a refusal by policy names the algorithm that was
    /// offered and the set that would have been taken, and an unsigned token says it is unsigned.
    /// </para>
    /// </remarks>
    SignatureInvalid,

    /// <summary>
    /// No key of the issuer matches the token - the recoverable sibling of
    /// <see cref="SignatureInvalid"/>: after a key rollover, refetching the issuer's keys may
    /// turn this into success, which a wrong signature never becomes.
    /// </summary>
    KeyNotFound,

    /// <summary>
    /// The "aud" claim does not name this receiver.
    /// </summary>
    AudienceMismatch,

    /// <summary>
    /// The "iat" claim is absent or outside the receiver's freshness window.
    /// </summary>
    IatOutOfRange,

    /// <summary>
    /// The token is encrypted and could not be decrypted.
    /// </summary>
    DecryptionFailed,

    /// <summary>
    /// A profile-specific step rejected the token; the description says why. This is the
    /// extension point for consumer profiles, whose failure modes this package cannot enumerate.
    /// </summary>
    Custom,
}