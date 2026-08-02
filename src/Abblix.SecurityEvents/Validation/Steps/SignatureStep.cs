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
        context.Require(SecurityEventTokenValidationStates.Parsed);

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
