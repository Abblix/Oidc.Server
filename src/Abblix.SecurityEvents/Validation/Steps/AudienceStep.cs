// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Validation.Steps;

/// <summary>
/// Requires the "aud" claim to name this receiver. RFC 8417 Section 2.2 only RECOMMENDS the
/// claim, but a receiver that skips the check accepts events addressed to somebody else - the
/// separate-audience strategy of Section 4.2 works only when audiences are actually checked - so
/// the default profile checks, and a receiver in a closed deployment removes the step as a named
/// decision rather than by leaving an option empty.
/// </summary>
public sealed class AudienceStep : ISecurityEventTokenValidator
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
