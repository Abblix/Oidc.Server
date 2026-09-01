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
    /// The signature does not verify against the issuer's keys, or it was made with an algorithm
    /// this receiver does not accept.
    /// </summary>
    /// <remarks>
    /// One code for two causes because a receiver answers both the same way, and because the wire
    /// word they share fits both: RFC 8935 Section 2.4 defines <c>invalid_key</c> as a key "invalid
    /// or otherwise unacceptable to the SET Recipient", and an algorithm outside the accepted set is
    /// unacceptable in exactly that sense. Which of the two happened is in
    /// <see cref="SecurityEventTokenValidationError.Description"/>, and a policy refusal's
    /// description names both the algorithm that was offered and the set that would have been taken.
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