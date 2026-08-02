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
/// The composite the step family collapses into: runs its members in order and stops at the first
/// error, so a step sees only tokens that survived everything before it.
/// </summary>
/// <remarks>
/// The family is composed through the dependency-injection machinery the rest of the product line
/// uses - members registered as ordinary <see cref="ISecurityEventTokenValidator"/>
/// implementations collapse behind the singular contract, and a consumer profile edits them in
/// place through the live composition cursor, inserting, replacing or removing steps without this
/// package changing. The constructor takes the member array that machinery hands to a composite.
/// </remarks>
public sealed class SecurityEventTokenValidatorComposite : ISecurityEventTokenValidator
{
    private readonly ISecurityEventTokenValidator[] _steps;

    /// <summary>
    /// Creates the composite over its members, in execution order.
    /// </summary>
    /// <param name="steps">The steps of the profile.</param>
    public SecurityEventTokenValidatorComposite(ISecurityEventTokenValidator[] steps)
    {
        if (steps is not { Length: > 0 })
        {
            throw new ArgumentException(
                "A pipeline with no steps would accept every token; an empty composition is a "
                + "configuration bug, not a permissive profile.",
                nameof(steps));
        }

        _steps = steps;
    }

    /// <inheritdoc />
    public async ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        foreach (var step in _steps)
        {
            var error = await step.ValidateAsync(context, cancellationToken);
            if (error is not null)
            {
                return error;
            }
        }

        return null;
    }
}
