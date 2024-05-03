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

namespace Abblix.Jwt;

/// <summary>
/// Represents the parameters used for validating a JSON Web Token (JWT).
/// </summary>
public record ValidationParameters
{
	/// <summary>
	/// Gets or sets the validation options.
	/// </summary>
	public ValidationOptions Options { get; init; } = ValidationOptions.Default;

	/// <summary>
	/// Gets or sets the delegate for issuer validation.
	/// </summary>
	public ValidateIssuersDelegate? ValidateIssuer { get; set; }

	/// <summary>
	/// Gets or sets the delegate for audience validation.
	/// </summary>
	public ValidateAudienceDelegate? ValidateAudience { get; set; }

	/// <summary>
	/// Gets or sets the delegate for resolving issuer signing keys.
	/// </summary>
	public ResolveIssuerSigningKeysDelegate? ResolveIssuerSigningKeys { get; set; }

	/// <summary>
	/// Gets or sets the delegate for resolving token decryption keys.
	/// </summary>
	public ResolveTokenDecryptionKeysDelegate? ResolveTokenDecryptionKeys { get; set; }

	/// <summary>
	/// Represents a delegate that asynchronously resolves a collection of JSON Web Keys (JWKs) for a given issuer,
	/// used for validating the signing of a JWT.
	/// </summary>
	/// <param name="issuer">The issuer for which to resolve the signing keys.</param>
	/// <returns>An asynchronous enumerable of JSON Web Keys.</returns>
	public delegate IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeysDelegate(string issuer);

	/// <summary>
	/// Represents a delegate that asynchronously resolves a collection of JSON Web Keys (JWKs) for a given issuer,
	/// used for token decryption.
	/// </summary>
	/// <param name="issuer">The issuer for which to resolve the decryption keys.</param>
	/// <returns>An asynchronous enumerable of JSON Web Keys.</returns>
	public delegate IAsyncEnumerable<JsonWebKey> ResolveTokenDecryptionKeysDelegate(string issuer);

	/// <summary>
	/// Represents a delegate that validates a set of audiences against a specific criterion.
	/// </summary>
	/// <param name="audiences">The audiences to validate.</param>
	/// <returns>A task that represents the asynchronous validation operation. The task result contains the validation outcome.</returns>
	public delegate Task<bool> ValidateAudienceDelegate(IEnumerable<string> audiences);

	/// <summary>
	/// Represents a delegate that validates an issuer against a specific criterion.
	/// </summary>
	/// <param name="issuer">The issuer to validate.</param>
	/// <returns>A task that represents the asynchronous validation operation. The task result contains the validation outcome.</returns>
	public delegate Task<bool> ValidateIssuersDelegate(string issuer);
};
