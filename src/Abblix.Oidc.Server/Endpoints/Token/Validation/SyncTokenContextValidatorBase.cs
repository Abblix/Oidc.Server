// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Provides a base class for implementing synchronous token context validators.
/// This class simplifies the creation of token context validators by offering a synchronous validation method
/// that is automatically wrapped in an asynchronous call.
/// </summary>
public abstract class SyncTokenContextValidatorBase : ITokenContextValidator
{
    /// <summary>
    /// Asynchronously validates the token request within the provided context by invoking the synchronous
    /// <see cref="Validate(TokenValidationContext)"/> method.
    /// </summary>
    /// <param name="context">
    /// The context containing the token request and related information that needs to be validated.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to a <see cref="OidcError"/> containing error details
    /// if the validation fails;
    /// otherwise, resolves to null indicating that the validation was successful.
    /// </returns>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Validates the token request within the provided context. This method must be implemented by derived classes
    /// to perform the specific validation logic.
    /// </summary>
    /// <param name="context">
    /// The context containing the token request and related information that needs to be validated.</param>
    /// <returns>
    /// A <see cref="OidcError"/> containing error details if the validation fails;
    /// otherwise, returns null indicating that the validation was successful.
    /// </returns>
    protected abstract OidcError? Validate(TokenValidationContext context);
}
