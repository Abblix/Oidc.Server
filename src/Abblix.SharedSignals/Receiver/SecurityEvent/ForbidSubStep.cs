// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

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
