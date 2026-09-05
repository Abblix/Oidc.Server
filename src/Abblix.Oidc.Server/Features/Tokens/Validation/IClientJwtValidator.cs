// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Defines a contract for validating JSON Web Tokens (JWTs) issued by clients, specifically for client authentication.
/// </summary>
/// <remarks>
/// This interface ensures that JWTs used in client authentication are properly validated according to
/// the specified options. It also retrieves client information associated with the validated JWT,
/// which is essential for authorizing client requests. Implementations of this interface should handle JWT validation,
/// including verifying the token's signature, issuer, audience and other claims.
/// </remarks>
public interface IClientJwtValidator
{
    /// <summary>
    /// Asynchronously validates a JWT and retrieves associated client information if the validation is successful.
    /// </summary>
    /// <param name="jwt">The JWT to validate.</param>
    /// <param name="options">Optional validation options that define the specific checks and constraints
    /// to apply during validation. Default is <see cref="ValidationOptions.Default"/>.</param>
    /// <returns>
    /// A task that returns a Result containing either a ValidJsonWebToken on success,
    /// or a JwtValidationError on failure.
    /// </returns>
    public Task<Result<ValidJsonWebToken, JwtValidationError>> ValidateAsync(
        string jwt, ValidationOptions options = ValidationOptions.Default);
}
