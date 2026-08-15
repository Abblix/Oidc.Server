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
