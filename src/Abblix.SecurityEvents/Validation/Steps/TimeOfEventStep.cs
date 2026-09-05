// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;

namespace Abblix.SecurityEvents.Validation.Steps;

/// <summary>
/// Requires the "toe" claim, where the transmitter chose to send one, to be a date the receiver can
/// read. Its absence is allowed - it is OPTIONAL (RFC 8417 Section 2.2) - and its value is not
/// judged, since a profile may make it approximate.
/// </summary>
/// <remarks>
/// The token is verified without lifetime handling, so nothing before the receiver's own code reads
/// this claim, and the accessor throws on a value it cannot read. Judged here, by name, so that a
/// receiver reading <see cref="SecurityEventToken.TimeOfEvent"/> afterwards meets either a date or
/// the absence the specification allows - never a value the transmitter wrote and nobody refused.
/// </remarks>
public sealed class TimeOfEventStep : ISecurityEventTokenValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        // A refusal on a claim's value is a judgement of the issuer's words, and those are only the
        // issuer's once the signature has been checked: the same precondition its neighbour holds.
        context.Require(SecurityEventTokenValidationStates.SignatureVerified);

        var error = context.Token!.Token.Payload.TryReadTimestamp(IanaClaimTypes.Toe, out _, out var whyUnreadable)
            ? null
            : new SecurityEventTokenValidationError(SecurityEventTokenErrorCode.MalformedToken, whyUnreadable);

        return ValueTask.FromResult(error);
    }
}
