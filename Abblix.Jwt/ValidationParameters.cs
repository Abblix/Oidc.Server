// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
