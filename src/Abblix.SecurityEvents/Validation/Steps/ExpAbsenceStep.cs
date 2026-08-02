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
/// Requires the claims to carry no "exp". Its absence is the wall between a SET and the ID and
/// access tokens an attacker would substitute one for (RFC 8417 Sections 4.1 and 4.2), so a token
/// carrying it is treated as another kind of JWT in a SET's clothing.
/// </summary>
/// <remarks>
/// The check is on the member's PRESENCE, not its parsed value: a malformed "exp" is exactly as
/// much a marker of a non-SET as a well-formed one, and a presence check cannot be fooled by a
/// value the parser fails to read. This is stricter than RFC 8417 Section 2.2's NOT RECOMMENDED,
/// deliberately: the builder on the transmitting side refuses to write the claim, and a receiver
/// this strict keeps the confusion wall standing even for issuers using other toolkits.
/// </remarks>
public sealed class ExpAbsenceStep : ISecurityCriticalValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.Parsed);

        SecurityEventTokenValidationError? error;
        if (context.UnverifiedPayload!.Json.ContainsKey(JwtClaimTypes.ExpiresAt))
        {
            error = new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.TokenConfusion,
                $"The claims carry '{JwtClaimTypes.ExpiresAt}', which a SET must not: its absence is what "
                + "separates a SET from the tokens it could be confused with (RFC 8417 Sections 4.1 and 4.2).");
        }
        else
        {
            context.Establish(SecurityEventTokenValidationStates.ExpAbsenceVerified);
            error = null;
        }

        return ValueTask.FromResult(error);
    }
}
