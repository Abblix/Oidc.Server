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
using Abblix.SecurityEvents.Validation;

namespace Abblix.SharedSignals.Receiver;

/// <summary>
/// Requires the claims to carry no "sub": SSF identifies the subject through the structured
/// top-level "sub_id" alone, and "The JWT 'sub' claim MUST NOT be present in any SET containing
/// an SSF event" (SSF 1.0 Section 4.1.2) - one of the restrictions Section 4.1.3 adds to keep
/// SSF SETs from being confused with other kinds of JWTs.
/// </summary>
/// <remarks>
/// The check is on the member's PRESENCE, before any signature work, for the same reasons the
/// core profile checks "exp" that way: a malformed "sub" marks a non-SSF token exactly as a
/// well-formed one does, and a rejection this cheap should not cost a signature check.
/// </remarks>
public sealed class ForbidSubStep : ISecurityCriticalValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.Parsed);

        var error = context.UnverifiedPayload!.Json.ContainsKey(JwtClaimTypes.Subject)
            ? new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.TokenConfusion,
                $"The claims carry '{JwtClaimTypes.Subject}', which a SET with an SSF event must not: the "
                + "subject travels in the top-level 'sub_id' alone (SSF 1.0 Section 4.1.2).")
            : null;

        return ValueTask.FromResult(error);
    }
}
