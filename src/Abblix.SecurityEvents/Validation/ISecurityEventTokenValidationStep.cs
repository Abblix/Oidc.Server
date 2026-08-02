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
/// </remarks>
public interface ISecurityEventTokenValidationStep
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

/// <summary>
/// Marks a validation step whose removal or replacement makes accepting a forged or mistyped
/// token possible. The pipeline builder refuses to touch such a step without an explicit,
/// reasoned acknowledgement - "temporarily for a test" must not ride into production silently.
/// </summary>
public interface ISecurityCriticalValidationStep : ISecurityEventTokenValidationStep;
