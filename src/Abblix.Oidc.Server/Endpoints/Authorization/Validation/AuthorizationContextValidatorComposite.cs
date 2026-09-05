// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Represents a composite validator for authorization contexts.
/// This class implements <see cref="IAuthorizationContextValidator"/> and aggregates multiple
/// validation steps into a single validation process.
/// </summary>
/// <param name="validators">An array of validators that define the validation process.</param>
public class AuthorizationContextValidatorComposite(IAuthorizationContextValidator[] validators) : IAuthorizationContextValidator
{
    /// <summary>
    /// Asynchronously validates an <see cref="AuthorizationValidationContext"/>.
    /// Iterates through each validation step, returning the first encountered error, if any.
    /// </summary>
    /// <param name="context">The authorization validation context to be validated.</param>
    /// <returns>
    /// A task that represents the asynchronous validation operation. The task result contains
    /// an <see cref="AuthorizationRequestValidationError"/> if a validation error is found, or null if validation succeeds.
    /// </returns>
    public Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
        => validators.FirstOrDefaultAsync(v => v.ValidateAsync(context));
}
