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
