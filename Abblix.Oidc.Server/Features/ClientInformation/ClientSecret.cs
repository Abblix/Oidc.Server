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

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Encapsulates the details of a client secret used in OAuth2 and OpenID Connect authentication flows.
/// </summary>
/// <remarks>
/// Client secrets are critical for the security of client applications, especially those that
/// authenticate in a server-side context. This record stores hashed versions of the secret
/// to enhance security by avoiding the storage of plain-text secrets. For client_secret_jwt
/// authentication method, the raw value must also be stored to validate HMAC-signed JWTs.
/// </remarks>
public record ClientSecret
{
	/// <summary>
	/// The raw value of the client secret. This property is required for client_secret_jwt
	/// authentication method where HMAC signature validation needs the original secret.
	/// </summary>
	/// <remarks>
	/// Storing the raw secret value reduces security compared to storing only hashes.
	/// Use this only when client_secret_jwt authentication method is required.
	/// For other authentication methods (client_secret_post, client_secret_basic),
	/// only the hashed values are needed.
	/// </remarks>
	public string? Value { get; init; }

	/// <summary>
	/// The SHA-256 hash of the client secret. This property is used to securely store
	/// and verify the secret without needing to store the plain text value.
	/// </summary>
	/// <remarks>
	/// The SHA-256 hash provides a secure way to handle client secrets, allowing
	/// for their verification during the authentication process without risking exposure.
	/// </remarks>
	public byte[]? Sha256Hash { get; init; }

	/// <summary>
	/// The SHA-512 hash of the client secret. This property offers an additional layer
	/// of security by using a stronger hashing algorithm compared to SHA-256.
	/// </summary>
	/// <remarks>
	/// SHA-512 hashes are more resistant to brute-force attacks due to their larger size
	/// and complexity. This property is optional and can be used in systems requiring
	/// heightened security measures.
	/// </remarks>
	public byte[]? Sha512Hash { get; init; }

	/// <summary>
	/// The expiration date and time for the client secret. Secrets past this date are considered
	/// invalid and cannot be used for authentication.
	/// </summary>
	/// <remarks>
	/// Setting an expiration date for client secrets is a best practice that helps mitigate
	/// the risk of secret compromise over time. It encourages regular rotation of secrets
	/// to maintain the security integrity of client applications.
	/// </remarks>
	public DateTimeOffset? ExpiresAt { get; init; }
}
