// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
