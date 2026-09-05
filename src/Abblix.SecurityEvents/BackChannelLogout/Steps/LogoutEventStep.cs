// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Validation;

namespace Abblix.SecurityEvents.BackChannelLogout.Steps;

/// <summary>
/// Requires the <c>events</c> claim to name the back-channel logout event - step 6 of OpenID
/// Connect Back-Channel Logout 1.0 Section 2.6.
/// </summary>
/// <remarks>
/// This is what makes the token a logout order rather than some other event the same issuer signed
/// for the same audience. Without it any such token would be accepted here and end a session,
/// which is the cross-JWT confusion Section 4.1 names.
/// <para>
/// The step above requires the claim to exist at all; this one requires what it says. The two are
/// separate because the profile inherits the first from the security-event defaults, where every
/// SET carries events, and only the member name is particular to logout.
/// </para>
/// </remarks>
public sealed class LogoutEventStep : ISecurityEventTokenValidator
{
    /// <inheritdoc />
    public async ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(
            SecurityEventTokenValidationStates.SignatureVerified |
            SecurityEventTokenValidationStates.EventsPresent);

        if (context is not { Token.Events: { } events } || !events.Contains(LogoutTokenClaims.BackChannelLogoutEvent))
        {
            return new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.Custom,
                "The events claim carries no back-channel logout statement.");
        }

        return null;
    }
}
