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

namespace Abblix.SecurityEvents.Validation.Steps;

/// <summary>
/// Requires the "iat" claim to be present - it is REQUIRED (RFC 8417 Section 2.2) - and within
/// the receiver's freshness window on either side of its clock.
/// </summary>
/// <remarks>
/// A SET records history, so freshness is not about token expiry - a SET deliberately has no
/// "exp" - but about bounding what a replay cache must remember: a token older than the window
/// fails here, so the cache can evict identifiers older than the window instead of keeping all of
/// them forever. The same tolerance forgives clock skew for a token from the near future, the
/// caution RFC 8417 Section 5.3 raises about treating timestamps as exact across distributed
/// systems.
/// </remarks>
/// <param name="clock">The receiver's clock; a test hands in a fake to pin the window.</param>
public sealed class IssuedAtWindowStep(TimeProvider clock) : ISecurityEventTokenValidationStep
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationState.SignatureVerified);

        var now = clock.GetUtcNow();
        var tolerance = context.Options.IssuedAtTolerance;

        var description = context.Token!.IssuedAt switch
        {
            null => $"The claims carry no '{JwtClaimTypes.IssuedAt}' member (RFC 8417 Section 2.2).",
            var issuedAt when issuedAt > now + tolerance =>
                $"The token claims to be issued at {issuedAt:O}, further in the future than the "
                + $"{tolerance} tolerance allows.",
            var issuedAt when issuedAt < now - tolerance =>
                $"The token was issued at {issuedAt:O}, older than the {tolerance} tolerance allows.",
            _ => null,
        };

        SecurityEventTokenValidationError? error;
        if (description is null)
        {
            context.Establish(SecurityEventTokenValidationState.IssuedAtVerified);
            error = null;
        }
        else
        {
            error = new SecurityEventTokenValidationError(SecurityEventTokenErrorCode.IatOutOfRange, description);
        }

        return ValueTask.FromResult(error);
    }
}
