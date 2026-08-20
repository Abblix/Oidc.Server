// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Abstractions;

namespace Abblix.SecurityEvents.Validation.Steps;

/// <summary>
/// Verifies the token's signature and, on success, promotes the claims from parsed shape to the
/// issuer's words: this is the step that sets the context's validated token, which every step
/// reading trusted claims requires.
/// </summary>
/// <remarks>
/// The verification itself lives behind <see cref="ISecurityEventTokenVerifier"/>, which owns key
/// resolution and the algorithm allowlist and hands back the verified token against the exact
/// bytes received - RFC 8417 Section 5.1: unless integrity is ensured by other means, a SET
/// "MUST be signed using JWS by an issuer that is trusted to do so for the use case".
/// </remarks>
/// <param name="verifier">The bridge to the host's cryptography.</param>
public sealed class SignatureStep(ISecurityEventTokenVerifier verifier) : ISecurityCriticalValidator
{
    /// <inheritdoc />
    public async ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        // The issuer decides which key set is fetched, so it must have been accepted before that
        // fetch is made. Ordering this by the state rather than by where the step sits in a list is
        // what makes a profile that lists them the wrong way round fail loudly instead of resolving
        // keys for an issuer nobody vouched for.
        context.Require(
            SecurityEventTokenValidationStates.Parsed | SecurityEventTokenValidationStates.IssuerAccepted);

        var result = await verifier.VerifyAsync(
            context.CompactToken,
            context.UnverifiedHeader!.KeyId,
            cancellationToken);

        if (!result.TryGetSuccess(out var token))
        {
            return result.GetFailure();
        }

        context.Token = new SecurityEventToken(token);
        context.Establish(SecurityEventTokenValidationStates.SignatureVerified);
        return null;
    }
}
