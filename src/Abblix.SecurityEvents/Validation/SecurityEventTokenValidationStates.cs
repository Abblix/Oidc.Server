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
/// The facts a validation pipeline has established so far about the token in flight. Each step
/// records what it proved, and a step whose safety depends on an earlier proof declares that
/// through <see cref="SecurityEventTokenValidationContext.Require"/> - which is what turns a
/// mis-ordered pipeline into a loud first-run failure instead of a silently skipped check.
/// </summary>
[Flags]
public enum SecurityEventTokenValidationStates
{
    /// <summary>
    /// Nothing established yet: the token is an opaque string.
    /// </summary>
    None = 0,

    /// <summary>
    /// The compact serialization was taken apart and its header and claims parsed. The parsed
    /// values are NOT yet trustworthy - parsing establishes shape, only a verified signature
    /// establishes authorship.
    /// </summary>
    Parsed = 1 << 0,

    /// <summary>
    /// The "typ" header names a SET (RFC 8417 Section 2.3).
    /// </summary>
    TypVerified = 1 << 1,

    /// <summary>
    /// The claims carry no "exp" - the marker whose absence separates a SET from the ID and
    /// access tokens it could be confused with (RFC 8417 Sections 4.1 and 4.2).
    /// </summary>
    ExpAbsenceVerified = 1 << 2,

    /// <summary>
    /// The "events" claim is present, is a JSON object, and holds at least one statement
    /// (RFC 8417 Section 2.2).
    /// </summary>
    EventsPresent = 1 << 3,

    /// <summary>
    /// The "iss" claim names an issuer this receiver accepts events from.
    /// </summary>
    IssuerAccepted = 1 << 4,

    /// <summary>
    /// The signature was verified against the issuer's keys. From here on the claims are the
    /// issuer's words, not just well-formed JSON.
    /// </summary>
    SignatureVerified = 1 << 5,

    /// <summary>
    /// The "aud" claim names this receiver.
    /// </summary>
    AudienceVerified = 1 << 6,

    /// <summary>
    /// The "iat" claim is present and within the receiver's freshness window.
    /// </summary>
    IssuedAtVerified = 1 << 7,

    /// <summary>
    /// Every event payload was deserialized through the registry - into its registered model or
    /// the raw passthrough.
    /// </summary>
    PayloadsDeserialized = 1 << 8,
}
