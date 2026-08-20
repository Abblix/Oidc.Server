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
/// Requires a <c>sub</c>, a <c>sid</c>, or both - step 5 of OpenID Connect Back-Channel Logout 1.0
/// Section 2.6.
/// </summary>
/// <remarks>
/// A token carrying neither says a session ended without saying whose, and Section 2.7 leaves
/// nothing to act on: the RP is asked to "locate the session(s) identified by the iss and sub
/// Claims and/or the sid Claim". A receiver that accepted it would either do nothing and answer
/// success to a request it did not honour, or end every session it holds for that issuer.
/// <para>
/// Read after the signature, unlike the cheap presence checks above: these two are the claims the
/// host acts on, so they must be the issuer's statements rather than the sender's.
/// </para>
/// </remarks>
public sealed class SubjectOrSessionStep : ISecurityEventTokenValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.SignatureVerified);

        var payload = context.Token!.Token.Payload;
        var error = payload.Subject is not null || payload.SessionId is not null
            ? null
            : new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.Custom,
                $"A Logout Token names its target through '{JwtClaimTypes.Subject}', "
                + $"'{IanaClaimTypes.Sid}', or both; this one has neither.");

        return ValueTask.FromResult(error);
    }
}
