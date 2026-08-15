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

namespace Abblix.SecurityEvents.BackChannelLogout;

/// <summary>
/// Refuses a Logout Token that carries a <c>nonce</c> - step 7 of OpenID Connect Back-Channel
/// Logout 1.0 Section 2.6.
/// </summary>
/// <remarks>
/// The prohibition protects the other endpoint, not this one. Section 2.4 says why the claim is
/// banned: a nonce "is prohibited to make a Logout Token syntactically invalid if used in a forged
/// Authentication Response in place of an ID Token". So refusing it here is this receiver keeping
/// its half of an agreement that guards the authorization callback - which is also why the check
/// belongs in every deployment and not only in those worried about their own logout endpoint.
/// <para>
/// Checked before the signature, on the member's presence, because a malformed nonce marks the
/// token exactly as a well-formed one does and a rejection this cheap should not cost a signature
/// verification.
/// </para>
/// </remarks>
public sealed class ForbidNonceStep : ISecurityEventTokenValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.Parsed);

        var error = context.UnverifiedPayload!.Json.ContainsKey(JwtClaimTypes.Nonce)
            ? new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.TokenConfusion,
                $"The claims carry '{JwtClaimTypes.Nonce}', which a Logout Token must not "
                + "(OpenID Connect Back-Channel Logout 1.0 Section 2.4).")
            : null;

        return ValueTask.FromResult(error);
    }
}
