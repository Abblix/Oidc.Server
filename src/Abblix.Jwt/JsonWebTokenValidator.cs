// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Represents a validator for JSON Web Tokens (JWTs) which validates a JWT against specified validation parameters.
/// </summary>
/// <remarks>
/// A Facade: it tells a JWS from a JWE and hands each to its side, <see cref="JwsValidation"/> or
/// <see cref="JweValidation"/>; a JWE is decrypted and the JWS it carries validated as any other.
/// </remarks>
/// <param name="jws">Validates a JWS through the header chain and the claims chain.</param>
/// <param name="jwe">Decrypts a JWE to the JWS it carries.</param>
internal class JsonWebTokenValidator(JwsValidation jws, JweValidation jwe) : IJsonWebTokenValidator
{

    /// <summary>
    /// Provides a collection of signing algorithms supported by the validator.
    /// Dynamically determined from registered signers in the dependency injection container.
    /// </summary>
    public IEnumerable<string> SigningAlgorithmsSupported => jws.SigningAlgorithmsSupported;

    /// <summary>
    /// Provides the JWE key-management algorithms (the <c>alg</c> values) the validator can decrypt.
    /// Dynamically determined from registered key encryptors in the dependency injection container.
    /// </summary>
    public IEnumerable<string> EncryptionAlgorithmsSupported => jwe.EncryptionAlgorithmsSupported;

    /// <summary>
    /// Provides the JWE content-encryption algorithms (the <c>enc</c> values) the validator can decrypt.
    /// Dynamically determined from registered content encryptors in the dependency injection container.
    /// </summary>
    public IEnumerable<string> EncryptionMethodsSupported => jwe.EncryptionMethodsSupported;

    /// <summary>
    /// Asynchronously validates a JWT string against specified validation parameters.
    /// </summary>
    /// <param name="jwt">The JWT string to validate.</param>
    /// <param name="parameters">The parameters defining the validation rules and requirements.</param>
    /// <returns>A task representing the validation operation,
    /// with a result containing either a validated JsonWebToken or a JwtValidationError.</returns>
    public async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        string jwt,
        ValidationParameters parameters)
    {
        // Refused before the token is read: a validation that names no token types is a host's mistake rather than a
        // property of the token
        if (parameters.TokenTypes is null)
        {
            throw new ArgumentException(
                $"{nameof(ValidationParameters)}.{nameof(ValidationParameters.TokenTypes)} must name the token types " +
                "this validation accepts.",
                nameof(parameters));
        }

        if (string.IsNullOrWhiteSpace(jwt))
            return new JwtValidationError(JwtError.MalformedToken, "JWT is null or empty");

        var jwtParts = jwt.Split('.');
        return jwtParts.Length switch
        {
            3 => await jws.ValidateAsync(jwtParts, parameters),
            5 => await (await jwe.DecryptAsync(jwtParts, parameters))
                .BindAsync(innerJwt => ValidateAsync(innerJwt, parameters)),
            _ => new JwtValidationError(
                JwtError.MalformedToken,
                $"Invalid JWT format: expected 3 or 5 dot-separated parts, got {jwtParts.Length}"),
        };
    }
}
