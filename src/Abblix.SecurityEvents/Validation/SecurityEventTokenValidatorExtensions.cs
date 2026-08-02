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

using Abblix.Utils;

namespace Abblix.SecurityEvents.Validation;

/// <summary>
/// The consumer-facing entry into validation: one call that runs a compact token through a
/// validator and shapes the outcome into the result a consumer acts on. Defined over the
/// interface rather than a class of its own, because after composition the resolved
/// <see cref="ISecurityEventTokenValidator"/> IS the whole profile - there is no separate driver
/// to name, hold or inject.
/// </summary>
public static class SecurityEventTokenValidatorExtensions
{
    /// <summary>
    /// Validates a token.
    /// </summary>
    /// <param name="validator">The validation profile - typically the composed pipeline.</param>
    /// <param name="compactToken">The token as received, in compact serialization.</param>
    /// <param name="options">What this run expects of the token.</param>
    /// <param name="cancellationToken">Cancels I/O the validators perform, such as key retrieval.</param>
    /// <returns>
    /// The validated token with its typed payloads, or the first error a validator reported.</returns>
    /// <exception cref="InvalidOperationException">
    /// Every check passed but none produced a validated token. A profile that removes the
    /// signature step must still set the context's token from a validator of its own - the
    /// exception is what keeps that omission from surfacing as a null to the consumer.</exception>
    public static async Task<Result<ValidatedSecurityEventToken, SecurityEventTokenValidationError>> ValidateAsync(
        this ISecurityEventTokenValidator validator,
        string compactToken,
        SecurityEventTokenValidationOptions options,
        CancellationToken cancellationToken = default)
    {
        var context = new SecurityEventTokenValidationContext(compactToken, options);

        var error = await validator.ValidateAsync(context, cancellationToken);
        if (error is not null)
        {
            return error;
        }

        if (context.Token is null)
        {
            throw new InvalidOperationException(
                "Every check passed but none set the validated token; a profile composed without "
                + "the signature step must produce the token from a validator of its own.");
        }

        return new ValidatedSecurityEventToken(context.Token, context.EventPayloads);
    }
}
