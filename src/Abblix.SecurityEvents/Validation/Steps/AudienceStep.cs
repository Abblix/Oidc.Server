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

namespace Abblix.SecurityEvents.Validation.Steps;

/// <summary>
/// Requires the "aud" claim to name this receiver. RFC 8417 Section 2.2 only RECOMMENDS the
/// claim, but a receiver that skips the check accepts events addressed to somebody else - the
/// separate-audience strategy of Section 4.2 works only when audiences are actually checked - so
/// the default profile checks, and a receiver in a closed deployment removes the step as a named
/// decision rather than by leaving an option empty.
/// </summary>
public sealed class AudienceStep : ISecurityEventTokenValidationStep
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.SignatureVerified);

        // A missing expectation is a configuration bug, not a token defect: reporting it as a
        // token error would let a receiver run for months rejecting everything - or, with the
        // check inverted, accepting everything - while the logs blame the tokens.
        var expected = context.Options.ExpectedAudience;
        if (string.IsNullOrEmpty(expected))
        {
            throw new InvalidOperationException(
                $"{nameof(AudienceStep)} requires {nameof(SecurityEventTokenValidationOptions.ExpectedAudience)} "
                + "to be configured; a profile that does not check audiences removes the step instead.");
        }

        SecurityEventTokenValidationError? error;
        if (context.Token!.Audiences.Contains(expected, StringComparer.Ordinal))
        {
            context.Establish(SecurityEventTokenValidationStates.AudienceVerified);
            error = null;
        }
        else
        {
            error = new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.AudienceMismatch,
                $"The token's audiences do not include '{expected}'.");
        }

        return ValueTask.FromResult(error);
    }
}
