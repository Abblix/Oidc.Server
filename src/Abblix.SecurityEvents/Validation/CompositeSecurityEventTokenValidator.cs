// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
public sealed class CompositeSecurityEventTokenValidator(ISecurityEventTokenValidator[] steps)
    : ISecurityEventTokenValidator
{
    private readonly ISecurityEventTokenValidator[] _steps = steps is { Length: > 0 }
        ? steps
        : throw new ArgumentException(
            "A composite with no members would accept every token; an empty composition is a "
            + "configuration bug, not a permissive profile.",
            nameof(steps));

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
