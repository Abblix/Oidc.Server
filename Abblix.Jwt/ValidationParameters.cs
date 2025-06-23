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
/// Defines parameters used during the validation of a JSON Web Token (JWT).
/// </summary>
public record ValidationParameters
{
	/// <summary>
	/// Options that control various aspects of JWT validation.
	/// </summary>
	public ValidationOptions Options { get; init; } = ValidationOptions.Default;

	/// <summary>
	/// Delegate used to verify the validity of a token issuer.
	/// </summary>
	public ValidateIssuersDelegate? ValidateIssuer { get; set; }

	/// <summary>
	/// Delegate used to validate one or more token audiences.
	/// </summary>
	public ValidateAudienceDelegate? ValidateAudience { get; set; }

	/// <summary>
	/// Delegate that resolves the signing keys for a given issuer, used during token signature validation.
	/// </summary>
	public ResolveIssuerSigningKeysDelegate? ResolveIssuerSigningKeys { get; set; }

	/// <summary>
	/// Delegate that resolves decryption keys for a given issuer, used during token decryption.
	/// </summary>
	public ResolveTokenDecryptionKeysDelegate? ResolveTokenDecryptionKeys { get; set; }

	/// <summary>
	/// Time window applied to accommodate clock discrepancies when validating timestamps.
	/// </summary>
	public TimeSpan ClockSkew { get; set; } = TimeSpan.Zero;

	/// <summary>
	/// Resolves signing keys (JWKs) asynchronously for a specified issuer.
	/// </summary>
	/// <param name="issuer">Issuer whose signing keys are to be resolved.</param>
	/// <returns>An asynchronous stream of JSON Web Keys.</returns>
	public delegate IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeysDelegate(string issuer);

	/// <summary>
	/// Resolves decryption keys (JWKs) asynchronously for a specified issuer.
	/// </summary>
	/// <param name="issuer">Issuer whose decryption keys are to be resolved.</param>
	/// <returns>An asynchronous stream of JSON Web Keys.</returns>
	public delegate IAsyncEnumerable<JsonWebKey> ResolveTokenDecryptionKeysDelegate(string issuer);

	/// <summary>
	/// Validates a collection of audiences against expected values.
	/// </summary>
	/// <param name="audiences">Audiences to be validated.</param>
	/// <returns>A task that returns true if validation succeeds.</returns>
	public delegate Task<bool> ValidateAudienceDelegate(IEnumerable<string> audiences);

	/// <summary>
	/// Validates a token issuer against expected values.
	/// </summary>
	/// <param name="issuer">Issuer to be validated.</param>
	/// <returns>A task that returns true if validation succeeds.</returns>
	public delegate Task<bool> ValidateIssuersDelegate(string issuer);
};
