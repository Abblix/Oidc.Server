// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Defines the contract for a service that validates JSON Web Tokens (JWTs).
/// </summary>
public interface IJsonWebTokenValidator
{
	/// <summary>
	/// Indicates which algorithms are accepted by the validator for verifying the signatures of incoming JWTs,
	/// ensuring that only tokens signed with recognized and secure algorithms are considered valid.
	/// </summary>
	IEnumerable<string> SigningAlgorithmsSupported { get; }

	/// <summary>
	/// Indicates which JWE key-management algorithms (the <c>alg</c> header values, e.g. "RSA-OAEP-256")
	/// the validator can use to decrypt incoming encrypted JWTs, such as JWE-wrapped request objects.
	/// </summary>
	IEnumerable<string> EncryptionAlgorithmsSupported { get; }

	/// <summary>
	/// Indicates which JWE content-encryption algorithms (the <c>enc</c> header values, e.g. "A256GCM")
	/// the validator can use to decrypt incoming encrypted JWTs, such as JWE-wrapped request objects.
	/// </summary>
	IEnumerable<string> EncryptionMethodsSupported { get; }

	/// <summary>
	/// Asynchronously validates a JWT against a set of specified parameters.
	/// </summary>
	/// <param name="jwt">The JWT as a string to be validated.</param>
	/// <param name="parameters">The parameters against which the JWT will be validated.</param>
	/// <returns>A Task representing the asynchronous validation operation, which yields a Result containing either
	/// a validated JsonWebToken or a JwtValidationError.</returns>
	Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(string jwt, ValidationParameters parameters);
}
