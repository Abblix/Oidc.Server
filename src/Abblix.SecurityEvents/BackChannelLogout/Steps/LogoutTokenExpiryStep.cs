// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SecurityEvents.BackChannelLogout.Steps;

/// <summary>
/// Requires <c>exp</c> to be present and still in the future, inverting the rule of the step it
/// replaces.
/// </summary>
/// <remarks>
/// OpenID Connect Back-Channel Logout 1.0 Section 2.6 step 4 asks that the "iss, aud, iat, and exp
/// Claims" be validated "in the same way they are validated in ID Tokens", where OpenID Connect
/// Core 1.0 Section 2 makes <c>exp</c> REQUIRED. A SET forbids the same claim, which is why this
/// replacement exists rather than an addition: the two rules cannot both hold, and a profile
/// carrying both would refuse every token either way.
/// <para>
/// The expiry is what bounds how long a captured Logout Token stays usable, which Section 4 asks
/// providers to keep short - "preferably at most two minutes in the future, to prevent captured
/// Logout Tokens from being replayable". The replay guard covers that window; this step is what
/// makes the window finite, so the guard has something to forget.
/// </para>
/// <para>
/// The same tolerance the profile allows an issue time is allowed here, for the reason RFC 8417
/// Section 5.3 gives about timestamps across distributed systems: the receiver's clock is not the
/// issuer's.
/// </para>
/// Security-critical, because it replaces a critical step and polices the same claim with the
/// opposite sign. It deliberately does not establish the state that step establishes: that flag
/// says the claim is ABSENT, which is the answer this profile gives the other way round, and a
/// later step asking for it would be asking a question this profile answers differently.
/// </remarks>
/// <param name="clock">The receiver's clock; a test hands in a fake to pin the window.</param>
public sealed class LogoutTokenExpiryStep(TimeProvider clock) : ISecurityCriticalValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.Parsed);

        var now = clock.GetUtcNow();
        var tolerance = context.Options.IssuedAtTolerance;

        var description = context.UnverifiedPayload!.ExpiresAt switch
        {
            null => $"The claims carry no '{JwtClaimTypes.ExpiresAt}' member, which a Logout Token "
                    + "requires (OpenID Connect Back-Channel Logout 1.0 Section 2.6).",
            var expiresAt when expiresAt < now - tolerance =>
                $"The Logout Token expired at {expiresAt:O}, further past than the {tolerance} tolerance "
                + "allows.",
            _ => null,
        };

        return ValueTask.FromResult(description is not null
            ? new SecurityEventTokenValidationError(SecurityEventTokenErrorCode.Custom, description)
            : null);
    }
}
