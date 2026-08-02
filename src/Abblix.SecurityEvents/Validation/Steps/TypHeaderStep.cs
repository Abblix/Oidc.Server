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
/// Requires the "typ" header to name a SET. A JWT accepted as a SET, or the reverse, is the token
/// confusion class RFC 8417 Section 4 is about, and the explicit type is its most direct wall
/// (Section 4.3).
/// </summary>
/// <remarks>
/// RFC 8417 Section 2.3 makes the header conditional - it "MUST be included if the SET could be
/// used in an application context in which it could be confused with other kinds of JWTs" - and
/// this profile takes the condition as met: a receiver cannot know every context its issuers'
/// JWTs live in, so it assumes the confusable one. The comparison accepts every spelling
/// RFC 7515 Section 4.1.9 makes equivalent, "application/secevent+jwt" included. A profile whose
/// tokens are typed differently - Back-Channel Logout's "logout+jwt", say - replaces this step
/// with its own rather than removing typing altogether.
/// </remarks>
public sealed class TypHeaderStep : ISecurityCriticalValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.Parsed);

        var type = context.UnverifiedHeader!.Type;

        SecurityEventTokenValidationError? error;
        if (JwtTypeName.Matches(type, SecurityEventToken.TokenType))
        {
            context.Establish(SecurityEventTokenValidationStates.TypVerified);
            error = null;
        }
        else
        {
            error = new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.TokenConfusion,
                type is null
                    ? "The token carries no 'typ' header; this profile requires explicit SET typing "
                      + "(RFC 8417 Section 2.3)."
                    : $"The 'typ' header is '{type}', not '{SecurityEventToken.TokenType}': the token is not "
                      + "a SET (RFC 8417 Section 2.3).");
        }

        return ValueTask.FromResult(error);
    }
}
