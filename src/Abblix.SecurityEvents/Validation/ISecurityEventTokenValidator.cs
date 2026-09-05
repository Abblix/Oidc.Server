// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Validation;

/// <summary>
/// One check in the validation pipeline. The validator runs steps in order and stops at the first
/// error, so a step sees only tokens that survived everything before it.
/// </summary>
/// <remarks>
/// A step's contract, beyond the signature: declare the facts your safety depends on through
/// <see cref="SecurityEventTokenValidationContext.Require"/> before reading them, record what you
/// proved through <see cref="SecurityEventTokenValidationContext.Establish"/>, and stay free of
/// side effects - validation answers "is this token acceptable", and anything that changes the
/// world on the strength of that answer (registering a replay identifier, invalidating a cache)
/// belongs after the verdict, in the consumer. That split is why replay protection is not a step:
/// registering a "jti" is a mutation, and a pipeline that mutated on a token later steps might
/// still reject would need an undo.
/// <para>
/// The return type is <see cref="ValueTask{TResult}"/> deliberately: all but one of the default
/// steps answer synchronously - only signature verification performs I/O, for key retrieval -
/// and the pipeline calls every step on every token, so a <see cref="Task{TResult}"/> here would
/// allocate once per synchronous step per token for nothing. The usual ValueTask hazard, a
/// second await, has no doorway: the composite and the guard each await a step exactly once.
/// </para>
/// </remarks>
public interface ISecurityEventTokenValidator
{
    /// <summary>
    /// Checks the token in flight.
    /// </summary>
    /// <param name="context">The state accumulated by earlier steps.</param>
    /// <param name="cancellationToken">Cancels I/O the step performs, such as key retrieval.</param>
    /// <returns>Null to pass the token on; an error to stop the pipeline with that verdict.</returns>
    ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken);
}
