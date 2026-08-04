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
/// What one validation run expects of the token: the per-call half of the receiver's
/// configuration, as opposed to the pipeline composition and key resolution, which are wired
/// once.
/// </summary>
public record SecurityEventTokenValidationOptions
{
    /// <summary>
    /// The audience value under which this receiver expects to be named in the "aud" claim.
    /// Required by the default pipeline's audience step; a profile that removes that step may
    /// leave it null.
    /// </summary>
    public string? ExpectedAudience { get; init; }

    /// <summary>
    /// The issuers this receiver accepts events from. An empty set accepts nobody - the safe
    /// reading of an unconfigured receiver - and the issuer step reports any other issuer as
    /// unknown.
    /// </summary>
    public IReadOnlyCollection<string> ExpectedIssuers { get; init; } = [];

    /// <summary>
    /// How far a token's "iat" may lie from the receiver's clock, in either direction: the same
    /// window forgives clock skew for a token from the near future and bounds staleness for one
    /// from the past. The bound matters beyond hygiene - a replay cache tracking received "jti"
    /// values (RFC 8417 Section 2.2 names that use) can evict entries older than the window
    /// instead of remembering every identifier forever, because anything older fails here first.
    /// </summary>
    public TimeSpan IssuedAtTolerance { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long past a token's issue time its identifier stays in the replay cache. It must
    /// cover <see cref="IssuedAtTolerance"/> with a margin, because an identifier forgotten
    /// while its token still passes the freshness window above is an identifier that token can
    /// replay on. The default doubles the default tolerance, and raising one without the other
    /// is the mistake this pairing is written side by side to prevent.
    /// </summary>
    public TimeSpan ReplayRetention { get; init; } = TimeSpan.FromMinutes(10);
}
