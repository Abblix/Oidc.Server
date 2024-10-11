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

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

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
    /// A task that represents the asynchronous operation. The task result is a tuple containing the validation result
    /// and the associated <see cref="ClientInfo"/> if the JWT is valid; otherwise, it returns null for the client info.
    /// </returns>
    public Task<(JwtValidationResult, ClientInfo?)> ValidateAsync(
        string jwt, ValidationOptions options = ValidationOptions.Default);
}
