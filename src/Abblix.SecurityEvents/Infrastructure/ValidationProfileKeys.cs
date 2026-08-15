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

using Abblix.Jwt;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// Names the validation profiles built over this core: each a keyed
/// <c>ISecurityEventTokenValidator</c> family that one consumer creates, edits and resolves, so
/// what one demands of its own kind of token never collides with what another demands of its.
/// </summary>
/// <remarks>
/// The keys live with the profile mechanism rather than with each consumer, because that is what
/// they are keys INTO - a profile is a shape of this core's pipeline, whatever specification asked
/// for that shape. Each value is the token kind's own <c>typ</c>, since that is precisely what
/// profiles part over: each pins a type and shapes the claims that type demands, so "which
/// profile" and "which kind of token" are one question with one spelling.
/// <para>
/// A second consumer of the SAME kind does not share a key with the first: a profile has one
/// owner, and that consumer names a key of its own. What is published here is one key per kind
/// this repository ships a profile for.
/// </para>
/// </remarks>
public static class ValidationProfileKeys
{
    /// <summary>
    /// The profile a plain Security Event Token is judged by (RFC 8417), which Shared Signals
    /// receivers shape further for their streams.
    /// </summary>
    /// <remarks>
    /// Public because a host that adds its OWN steps to a receiver's validation - a
    /// deployment-specific issuer pin, say - reaches the profile's cursor by this key.
    /// </remarks>
    public const string SecurityEvent = JsonWebTokenTypes.SecurityEvent;

    /// <summary>
    /// The profile a Logout Token is judged by, its type fixed by OpenID Connect Back-Channel
    /// Logout 1.0 Section 2.4.
    /// </summary>
    /// <remarks>
    /// The two readings stay spelled apart on purpose:
    /// <see cref="Abblix.Jwt.JsonWebTokenTypes.LogoutToken"/> stands wherever a WIRE value is meant
    /// - the header the profile pins, the header a fixture writes - and this name stands where the
    /// question is which profile.
    /// </remarks>
    public const string LogoutToken = JsonWebTokenTypes.LogoutToken;
}
