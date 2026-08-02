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
    /// The signature does not verify against the issuer's keys.
    /// </summary>
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

/// <summary>
/// A validation failure: the code a receiver branches on, and the sentence a log reader needs.
/// </summary>
/// <param name="Code">The failure class.</param>
/// <param name="Description">What exactly failed, in the words of the step that found it.</param>
public record SecurityEventTokenValidationError(SecurityEventTokenErrorCode Code, string Description)
{
    /// <summary>
    /// Returns the description - the half of the error a human reads.
    /// </summary>
    public override string ToString() => Description;
}
